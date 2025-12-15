//go:build mockserver
// +build mockserver

package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// Mock desktop configuration
var (
	mockDesktopMode     bool
	mockDesktopWidth    int
	mockDesktopHeight   int
	mockDesktopFPS      int
	mockFrameCount      int64
	mockWireFrameSeq    uint32
	mockDesktopEventID  []byte
	mockDesktopEventHex string
	mockDesktopEventMu  sync.RWMutex

	mockFSRoot string
	baseHTTP   string

	mockAudioUUID string
)

type fileEntry struct {
	Name string `json:"name"`
	Size uint64 `json:"size"`
	Time int64  `json:"time"`
	Type int    `json:"type"` // 0: file, 1: folder
}

// Packet represents a message packet
type Packet struct {
	Act   string                 `json:"act,omitempty"`
	Code  int                    `json:"code,omitempty"`
	Msg   string                 `json:"msg,omitempty"`
	Data  map[string]interface{} `json:"data,omitempty"`
	Event string                 `json:"event,omitempty"`
}

var (
	conn      *websocket.Conn
	secret    []byte
	connMutex sync.Mutex
	deviceID  string
)

func setMockDesktopSession(desktopHex string) {
	decoded, err := hex.DecodeString(strings.TrimSpace(desktopHex))
	if err != nil || len(decoded) != 16 {
		fmt.Printf("[MockDesktop] Invalid desktop session id: %q err=%v\n", desktopHex, err)
		return
	}
	mockDesktopEventMu.Lock()
	mockDesktopEventID = decoded
	mockDesktopEventHex = strings.ToLower(strings.TrimSpace(desktopHex))
	mockWireFrameSeq = 0
	mockFrameCount = 0
	mockDesktopEventMu.Unlock()
	fmt.Printf("[MockDesktop] Desktop session set: %s\n", mockDesktopEventHex)
}

func clearMockDesktopSession() {
	mockDesktopEventMu.Lock()
	mockDesktopEventID = nil
	mockDesktopEventHex = ""
	mockWireFrameSeq = 0
	mockFrameCount = 0
	mockDesktopEventMu.Unlock()
}

func getMockDesktopSession() ([]byte, string, bool) {
	mockDesktopEventMu.RLock()
	defer mockDesktopEventMu.RUnlock()
	if len(mockDesktopEventID) != 16 || mockDesktopEventHex == "" {
		return nil, "", false
	}
	event := make([]byte, 16)
	copy(event, mockDesktopEventID)
	return event, mockDesktopEventHex, true
}

func main() {
	host := flag.String("host", "localhost", "Server host")
	port := flag.Int("port", 8443, "Server port")
	salt := flag.String("salt", "testsalt1234567890123", "Server salt (must match config.json)")
	secure := flag.Bool("secure", false, "Use wss:// instead of ws://")
	uuidHex := flag.String("uuid-hex", "", "Fixed 16-byte UUID as 32 hex chars (deterministic E2E)")
	keyHex := flag.String("key-hex", "", "Fixed key as hex (optional). If empty and --uuid-hex set, uses plaintext UUID key format")
	noInteractive := flag.Bool("no-interactive", false, "Disable stdin command loop (for CI/E2E)")
	mockDesktop := flag.Bool("mock-desktop", false, "Enable mock desktop mode for E2E testing")
	mockWidth := flag.Int("mock-width", 1920, "Mock desktop width")
	mockHeight := flag.Int("mock-height", 1080, "Mock desktop height")
	mockFPS := flag.Int("mock-fps", 10, "Mock desktop FPS")
	mockOS := flag.String("mock-os", "linux", "Mock device OS (e.g., linux/windows/darwin)")
	mockFS := flag.Bool("mock-fs", true, "Enable mock file system handlers (E2E)")
	mockFSRootFlag := flag.String("mock-fs-root", "", "Mock file system root directory (optional; defaults to temp dir)")
	mockStandalone := flag.Bool("mock-standalone", false, "Run standalone mock desktop server (no Rocket connection)")
	mockListenPort := flag.Int("mock-port", 18081, "Standalone mock desktop server port")
	flag.Parse()

	// Set mock desktop globals
	mockDesktopMode = *mockDesktop
	mockDesktopWidth = *mockWidth
	mockDesktopHeight = *mockHeight
	mockDesktopFPS = *mockFPS

	// Standalone mock desktop server mode (used by Playwright E2E harness)
	if *mockStandalone {
		listenPort := *mockListenPort
		if *port != 8443 {
			listenPort = *port
		}
		if listenPort == 0 {
			listenPort = 18081
		}
		runStandaloneMockServer(listenPort, mockDesktopWidth, mockDesktopHeight, mockDesktopFPS)
		return
	}

	fmt.Println("=== Spark WebSocket Test Client ===")
	if mockDesktopMode {
		fmt.Printf("Mock Desktop Mode: %dx%d @ %d FPS\n", mockDesktopWidth, mockDesktopHeight, mockDesktopFPS)
	}
	fmt.Printf("Connecting to %s:%d (secure=%v)\n", *host, *port, *secure)
	baseHTTP = fmt.Sprintf("http://%s:%d", *host, *port)
	if *secure {
		baseHTTP = fmt.Sprintf("https://%s:%d", *host, *port)
	}

	if mockDesktopMode && *mockFS {
		var err error
		if strings.TrimSpace(*mockFSRootFlag) != "" {
			mockFSRoot, err = filepath.Abs(*mockFSRootFlag)
		} else {
			mockFSRoot, err = os.MkdirTemp("", "rocket-e2e-devicefs-*")
		}
		if err != nil {
			fmt.Printf("[MockFS] Failed to create root: %v\n", err)
			os.Exit(1)
		}
		if err := seedMockFS(mockFSRoot); err != nil {
			fmt.Printf("[MockFS] Failed to seed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[MockFS] Root: %s\n", mockFSRoot)
	}

	// Generate credentials
	var uuid []byte
	var key []byte
	var err error
	if strings.TrimSpace(*uuidHex) != "" {
		uuid, err = hex.DecodeString(strings.TrimSpace(*uuidHex))
		if err != nil || len(uuid) != 16 {
			fmt.Printf("Invalid --uuid-hex (must be 32 hex chars / 16 bytes): %v\n", err)
			os.Exit(1)
		}
		if strings.TrimSpace(*keyHex) != "" {
			key, err = hex.DecodeString(strings.TrimSpace(*keyHex))
			if err != nil {
				fmt.Printf("Invalid --key-hex: %v\n", err)
				os.Exit(1)
			}
		} else {
			// New-format auth: 16-byte key equals UUID.
			key = append([]byte(nil), uuid...)
		}
		fmt.Printf("Using fixed UUID: %s\n", hex.EncodeToString(uuid))
		fmt.Printf("Using fixed Key:  %s\n", hex.EncodeToString(key))
	} else {
		uuid, key = generateCredentials(*salt)
		fmt.Printf("Generated UUID: %s\n", hex.EncodeToString(uuid))
		fmt.Printf("Generated Key: %s\n", hex.EncodeToString(key))
	}

	// Connect to server
	scheme := "ws"
	if *secure {
		scheme = "wss"
	}
	url := fmt.Sprintf("%s://%s:%d/ws", scheme, *host, *port)

	headers := http.Header{}
	headers.Add("UUID", hex.EncodeToString(uuid))
	headers.Add("Key", hex.EncodeToString(key))

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	var resp *http.Response
	conn, resp, err = dialer.Dial(url, headers)
	if err != nil {
		fmt.Printf("Connection failed: %v\n", err)
		if resp != nil {
			fmt.Printf("HTTP Status: %d\n", resp.StatusCode)
		}
		os.Exit(1)
	}
	defer conn.Close()

	// Get secret from response header
	secretHex := resp.Header.Get("Secret")
	if secretHex == "" {
		fmt.Println("No secret received from server!")
		os.Exit(1)
	}
	secret, _ = hex.DecodeString(secretHex)
	fmt.Printf("Session secret received (%d bytes)\n", len(secret))
	fmt.Println("Connected successfully!")

	// Start message reader
	go readMessages()

	// Register device (required for Rocket to route sessions to this connection).
	if deviceID == "" {
		if mockDesktopMode {
			deviceID = "e2e-" + hex.EncodeToString(uuid)[:8]
		} else {
			deviceID = hex.EncodeToString(uuid)
		}
	}
	sendPacket(Packet{
		Act: "DEVICE_UP",
		Data: map[string]interface{}{
			"id": deviceID,
			"os": func() string {
				if mockDesktopMode {
					return *mockOS
				}
				return "windows"
			}(),
			"arch":     "amd64",
			"hostname": "Rocket E2E Mock",
			"username": "e2e",
		},
	})
	fmt.Printf("[E2E] Sent DEVICE_UP (id=%s)\n", deviceID)

	// Start mock desktop streaming if enabled
	if mockDesktopMode {
		go runMockDesktop()
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	if *noInteractive {
		fmt.Println("[E2E] no-interactive mode enabled; waiting for SIGINT/SIGTERM")
		<-sigChan
		fmt.Println("\nShutting down...")
		return
	}

	// Interactive command loop
	fmt.Println("Available commands:")
	fmt.Println("  list          - List connected devices")
	fmt.Println("  terminal <id> - Start terminal on device")
	fmt.Println("  desktop <id>  - Start desktop on device")
	fmt.Println("  webcam <id>   - List webcams on device")
	fmt.Println("  audio <id>    - List audio devices")
	fmt.Println("  screenshot <id> - Get screenshot")
	fmt.Println("  processes <id>  - List processes")
	fmt.Println("  files <id> [path] - List files")
	fmt.Println("  ping <id>     - Ping device")
	fmt.Println("  raw <json>    - Send raw JSON packet")
	fmt.Println("  quit          - Exit")
	if mockDesktopMode {
		fmt.Println("\nMock Desktop commands:")
		fmt.Println("  resolution <w> <h> - Change resolution")
		fmt.Println("  pong [source]      - Send DESKTOP_PONG")
		fmt.Println("  stats              - Show frame statistics")
	}
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")

	inputChan := make(chan string)
	go func() {
		for scanner.Scan() {
			inputChan <- scanner.Text()
		}
	}()

	for {
		select {
		case <-sigChan:
			fmt.Println("\nShutting down...")
			return
		case input := <-inputChan:
			handleCommand(input)
			fmt.Print("> ")
		}
	}
}

func generateCredentials(salt string) ([]byte, []byte) {
	// Generate random UUID
	uuid := make([]byte, 16)
	for i := range uuid {
		uuid[i] = byte(time.Now().UnixNano()>>(i*4)) ^ byte(i*17+42)
	}

	// Derive salt bytes (same as server)
	saltBytes := []byte(salt)
	padding := make([]byte, 24)
	for i := range padding {
		padding[i] = 25
	}
	saltBytes = append(saltBytes, padding...)
	saltBytes = saltBytes[:24]

	// Generate key: MD5(uuid) + AES-CTR-encrypt(uuid, saltBytes, MD5(uuid))
	hash := md5.Sum(uuid)
	block, _ := aes.NewCipher(saltBytes)
	stream := cipher.NewCTR(block, hash[:])
	encrypted := make([]byte, len(uuid))
	stream.XORKeyStream(encrypted, uuid)

	key := append(hash[:], encrypted...)
	return uuid, key
}

func readMessages() {
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			fmt.Printf("\nConnection closed: %v\n", err)
			os.Exit(0)
		}

		// Check if binary packet
		if len(data) > 5 && data[0] == 34 && data[1] == 22 && data[2] == 19 && data[3] == 17 {
			service := data[4]
			op := data[5]
			if mockDesktopMode && service == 21 && op == 0 && len(data) >= 24 {
				// Terminal stream input from browser -> echo back as output.
				event := make([]byte, 16)
				copy(event, data[6:22])
				payload := data[24:]
				echo := append([]byte("[echo] "), payload...)
				sendTerminalBinary(event, echo)
				continue
			}
			fmt.Printf("\n[BINARY] Service=%d Op=%d Len=%d\n", service, op, len(data))
			continue
		}

		// Rocket server uses plain JSON packets on the device control channel.
		var pack Packet
		if err := json.Unmarshal(data, &pack); err != nil {
			fmt.Printf("\n[RAW] %s\n", string(data))
			continue
		}

		// Pretty print
		prettyJSON, _ := json.MarshalIndent(pack, "", "  ")
		fmt.Printf("\n[RECV] %s\n", string(prettyJSON))

		// Store device ID if we get device info
		if pack.Act == "DEVICE_UPDATE" || pack.Act == "DEVICE_INFO" {
			if data, ok := pack.Data["id"].(string); ok {
				deviceID = data
				fmt.Printf("Device ID set to: %s\n", deviceID)
			}
		}

		// Respond to server ping (health check).
		if pack.Act == "PING" {
			sendPacket(Packet{Act: "PING", Code: 0, Event: pack.Event})
			continue
		}

		// Terminal init from server (E2E): acknowledge and send a welcome line.
		if mockDesktopMode && pack.Act == "TERMINAL_INIT" {
			sendPacket(Packet{Act: "TERMINAL_INIT", Code: 0, Event: pack.Event})
			if event, err := hex.DecodeString(pack.Event); err == nil && len(event) == 16 {
				sendTerminalBinary(event, []byte("Rocket E2E mock terminal ready\r\n"))
			}
			continue
		}

		if mockDesktopMode && pack.Act == "TERMINAL_KILL" {
			sendPacket(Packet{Act: "TERMINAL_QUIT", Code: 0, Event: pack.Event})
			continue
		}

		if mockDesktopMode && strings.HasPrefix(pack.Act, "AUDIO_") {
			handleMockAudio(pack)
			continue
		}

		// File operations (E2E).
		if mockDesktopMode && strings.HasPrefix(pack.Act, "FILES_") {
			handleMockFiles(pack)
			continue
		}

		// Desktop session init from server.
		if mockDesktopMode && pack.Act == "DESKTOP_INIT" {
			desktopHex := pack.Event
			if pack.Data != nil {
				if d, ok := pack.Data["desktop"].(string); ok && d != "" {
					desktopHex = d
				}
			}
			if desktopHex != "" {
				setMockDesktopSession(desktopHex)
				sendPacket(Packet{
					Act:   "DESKTOP_INIT",
					Code:  0,
					Event: desktopHex,
					Data: map[string]interface{}{
						"width":  mockDesktopWidth,
						"height": mockDesktopHeight,
						"monitors": []map[string]interface{}{
							{
								"id":     0,
								"name":   "MockDisplay",
								"width":  mockDesktopWidth,
								"height": mockDesktopHeight,
							},
						},
					},
				})
			}
			continue
		}

		// Echo input events for E2E test verification (mock-desktop mode)
		if mockDesktopMode && pack.Act == "DESKTOP_INPUT" {
			if events, ok := pack.Data["events"].([]interface{}); ok {
				fmt.Printf("[MockDesktop] INPUT_RECEIVED events=%d\n", len(events))
				for i, evt := range events {
					if evtMap, ok := evt.(map[string]interface{}); ok {
						fmt.Printf("[MockDesktop]   [%d] type=%v x=%v y=%v button=%v key=%v down=%v\n",
							i,
							evtMap["type"],
							evtMap["x"],
							evtMap["y"],
							evtMap["button"],
							evtMap["key"],
							evtMap["down"])
					}
				}
			}
		}

		// Echo ping requests and respond with pong (mock-desktop mode)
		if mockDesktopMode && pack.Act == "DESKTOP_PING" {
			fmt.Println("[MockDesktop] PING received, sending PONG")
			_, desktopHex, ok := getMockDesktopSession()
			if ok {
				sendPacket(Packet{
					Act:   "DESKTOP_PONG",
					Code:  0,
					Event: desktopHex,
					Data: map[string]interface{}{
						"source": "device",
					},
				})
			}
		}

		// Echo shot requests (mock-desktop mode)
		if mockDesktopMode && pack.Act == "DESKTOP_SHOT" {
			fmt.Println("[MockDesktop] SHOT request received, sending full frame")
			// Send a full-screen frame for the active desktop session
			if eventID, _, ok := getMockDesktopSession(); ok {
				sendMockFullFrame(eventID)
			}
		}

		// Echo config changes (mock-desktop mode)
		if mockDesktopMode && pack.Act == "DESKTOP_CONFIG" {
			fmt.Printf("[MockDesktop] CONFIG received: %+v\n", pack.Data)
		}

		if mockDesktopMode && pack.Act == "DESKTOP_KILL" {
			fmt.Println("[MockDesktop] KILL received, stopping desktop stream")
			clearMockDesktopSession()
		}
	}
}

func sendTerminalBinary(event []byte, payload []byte) {
	if len(event) != 16 {
		return
	}
	if len(payload) > 0xFFFF {
		payload = payload[:0xFFFF]
	}
	buf := make([]byte, 24+len(payload))
	copy(buf[0:6], []byte{34, 22, 19, 17, 21, 0})
	copy(buf[6:22], event)
	buf[22] = byte(len(payload) >> 8)
	buf[23] = byte(len(payload))
	copy(buf[24:], payload)
	connMutex.Lock()
	defer connMutex.Unlock()
	if conn != nil {
		_ = conn.WriteMessage(websocket.BinaryMessage, buf)
	}
}

func seedMockFS(root string) error {
	if err := os.MkdirAll(filepath.Join(root, "home", "e2e"), 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello from Rocket E2E\n"), 0644)
}

func handleMockAudio(pack Packet) {
	reply := func(code int, msg string, data map[string]any) {
		sendPacket(Packet{Act: pack.Act, Code: code, Msg: msg, Event: pack.Event, Data: data})
	}

	switch pack.Act {
	case "AUDIO_INIT":
		// Server uses Event as the audio session UUID.
		mockAudioUUID = pack.Event
		reply(0, "", nil)
		return

	case "AUDIO_LIST":
		reply(0, "", map[string]any{
			"devices": []map[string]any{
				{"id": "default", "name": "Mock Output"},
			},
		})
		return

	case "AUDIO_SELECT":
		// Start emitting a few AUDIO_DATA packets that will be forwarded to the browser audio WS.
		uuid := mockAudioUUID
		if pack.Data != nil {
			if v, ok := pack.Data["audio"].(string); ok && v != "" {
				uuid = v
			}
		}
		if uuid == "" {
			uuid = pack.Event
		}
		if uuid == "" {
			reply(1, "missing audio uuid", nil)
			return
		}

		go func(audioUUID string) {
			for i := 0; i < 3; i++ {
				payload := []byte("mock-opus-packet-" + fmt.Sprintf("%d", i))
				sendPacket(Packet{
					Act: "AUDIO_DATA",
					Data: map[string]any{
						"uuid":      audioUUID,
						"seq":       i,
						"timestamp": time.Now().UnixMilli(),
						"size":      len(payload),
						"data":      base64.StdEncoding.EncodeToString(payload),
					},
				})
				time.Sleep(80 * time.Millisecond)
			}
		}(uuid)

		reply(0, "", nil)
		return

	case "AUDIO_KILL", "AUDIO_PING", "AUDIO_STOP":
		reply(0, "", nil)
		return
	default:
		// Unknown audio packet; acknowledge to keep session alive.
		reply(0, "", nil)
		return
	}
}

func handleMockFiles(pack Packet) {
	reply := func(code int, msg string, data map[string]any) {
		sendPacket(Packet{Act: pack.Act, Code: code, Msg: msg, Event: pack.Event, Data: data})
	}

	if strings.TrimSpace(mockFSRoot) == "" {
		reply(1, "mock fs disabled", nil)
		return
	}

	switch pack.Act {
	case "FILES_LIST":
		p := "/"
		if v, ok := pack.Data["path"].(string); ok && strings.TrimSpace(v) != "" {
			p = v
		}
		local, err := resolveMockPath(p)
		if err != nil {
			reply(1, err.Error(), nil)
			return
		}
		entries, err := os.ReadDir(local)
		if err != nil {
			reply(1, err.Error(), nil)
			return
		}
		out := make([]fileEntry, 0, len(entries))
		for _, e := range entries {
			t := 0
			if e.IsDir() {
				t = 1
			}
			info, err := e.Info()
			if err != nil {
				out = append(out, fileEntry{Name: e.Name(), Type: t})
				continue
			}
			out = append(out, fileEntry{
				Name: e.Name(),
				Size: uint64(info.Size()),
				Time: info.ModTime().Unix(),
				Type: t,
			})
		}
		reply(0, "", map[string]any{"files": out})
		return

	case "FILES_MKDIR":
		p, _ := pack.Data["path"].(string)
		local, err := resolveMockPath(p)
		if err != nil {
			reply(1, err.Error(), nil)
			return
		}
		if err := os.MkdirAll(local, 0755); err != nil {
			reply(1, err.Error(), nil)
			return
		}
		reply(0, "", nil)
		return

	case "FILES_REMOVE":
		raw, ok := pack.Data["files"].([]any)
		if !ok || len(raw) == 0 {
			reply(1, "invalid files", nil)
			return
		}
		for _, v := range raw {
			s, ok := v.(string)
			if !ok {
				continue
			}
			local, err := resolveMockPath(s)
			if err != nil {
				reply(1, err.Error(), nil)
				return
			}
			_ = os.RemoveAll(local)
		}
		reply(0, "", nil)
		return

	case "FILES_MOVE":
		src, _ := pack.Data["src"].(string)
		dst, _ := pack.Data["dst"].(string)
		srcLocal, err := resolveMockPath(src)
		if err != nil {
			reply(1, err.Error(), nil)
			return
		}
		dstLocal, err := resolveMockPath(dst)
		if err != nil {
			reply(1, err.Error(), nil)
			return
		}
		if err := os.MkdirAll(filepath.Dir(dstLocal), 0755); err != nil {
			reply(1, err.Error(), nil)
			return
		}
		if err := os.Rename(srcLocal, dstLocal); err == nil {
			reply(0, "", nil)
			return
		}
		if err := copyPath(srcLocal, dstLocal); err != nil {
			reply(1, err.Error(), nil)
			return
		}
		_ = os.RemoveAll(srcLocal)
		reply(0, "", nil)
		return

	case "FILES_COPY":
		src, _ := pack.Data["src"].(string)
		dst, _ := pack.Data["dst"].(string)
		srcLocal, err := resolveMockPath(src)
		if err != nil {
			reply(1, err.Error(), nil)
			return
		}
		dstLocal, err := resolveMockPath(dst)
		if err != nil {
			reply(1, err.Error(), nil)
			return
		}
		if err := copyPath(srcLocal, dstLocal); err != nil {
			reply(1, err.Error(), nil)
			return
		}
		reply(0, "", nil)
		return

	case "FILES_FETCH":
		dir, _ := pack.Data["path"].(string)
		name, _ := pack.Data["file"].(string)
		bridge, _ := pack.Data["bridge"].(string)
		if strings.TrimSpace(dir) == "" || strings.TrimSpace(name) == "" || strings.TrimSpace(bridge) == "" {
			reply(1, "invalid fetch args", nil)
			return
		}
		dstDir, err := resolveMockPath(dir)
		if err != nil {
			reply(1, err.Error(), nil)
			return
		}
		if err := os.MkdirAll(dstDir, 0755); err != nil {
			reply(1, err.Error(), nil)
			return
		}
		dstFile := filepath.Join(dstDir, filepath.Base(name))
		if err := pullBridgeToFile(bridge, dstFile); err != nil {
			reply(1, err.Error(), nil)
			return
		}
		reply(0, "", nil)
		return

	default:
		reply(1, "unsupported mock file op", map[string]any{"act": pack.Act})
		return
	}
}

func resolveMockPath(remote string) (string, error) {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		remote = "/"
	}
	clean := path.Clean("/" + remote)
	clean = strings.TrimPrefix(clean, "/")
	local := filepath.Join(append([]string{mockFSRoot}, strings.Split(clean, "/")...)...)
	absLocal, err := filepath.Abs(local)
	if err != nil {
		return "", err
	}
	absRoot, err := filepath.Abs(mockFSRoot)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absRoot, absLocal)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("path escapes root")
	}
	return absLocal, nil
}

func copyPath(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return copyDir(src, dst)
	}
	return copyFile(src, dst, info.Mode())
}

func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func copyDir(src, dst string) error {
	src = filepath.Clean(src)
	dst = filepath.Clean(dst)
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, info.Mode()); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		sPath := filepath.Join(src, entry.Name())
		dPath := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			if err := copyDir(sPath, dPath); err != nil {
				return err
			}
			continue
		}
		fi, err := entry.Info()
		if err != nil {
			return err
		}
		if err := copyFile(sPath, dPath, fi.Mode()); err != nil {
			return err
		}
	}
	return nil
}

func pullBridgeToFile(bridgeID, dst string) error {
	url := fmt.Sprintf("%s/api/bridge/pull?bridge=%s", baseHTTP, bridgeID)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("bridge pull failed: %s %s", resp.Status, strings.TrimSpace(string(b)))
	}
	tmp := dst + ".tmp." + fmt.Sprintf("%d", time.Now().UnixNano())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	_ = f.Close()
	_ = os.Remove(dst)
	return os.Rename(tmp, dst)
}

func handleCommand(input string) {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return
	}

	cmd := strings.ToLower(parts[0])
	switch cmd {
	case "quit", "exit", "q":
		fmt.Println("Goodbye!")
		os.Exit(0)

	case "list":
		// In a real scenario, we'd query the server for devices
		// For now, show the current device
		if deviceID != "" {
			fmt.Printf("Current device: %s\n", deviceID)
		} else {
			fmt.Println("No device connected yet. Wait for DEVICE_UPDATE message.")
		}

	case "terminal":
		id := getDeviceID(parts)
		if id == "" {
			return
		}
		sendPacket(Packet{
			Act: "TERMINAL_INIT",
			Data: map[string]interface{}{
				"device":   id,
				"terminal": generateEventID(),
			},
		})

	case "desktop":
		id := getDeviceID(parts)
		if id == "" {
			return
		}
		sendPacket(Packet{
			Act: "DESKTOP_INIT",
			Data: map[string]interface{}{
				"device":  id,
				"desktop": generateEventID(),
			},
		})

	case "webcam":
		id := getDeviceID(parts)
		if id == "" {
			return
		}
		sendPacket(Packet{
			Act: "WEBCAM_LIST",
			Data: map[string]interface{}{
				"device": id,
			},
		})

	case "audio":
		id := getDeviceID(parts)
		if id == "" {
			return
		}
		sendPacket(Packet{
			Act: "AUDIO_LIST",
			Data: map[string]interface{}{
				"device": id,
			},
		})

	case "screenshot":
		id := getDeviceID(parts)
		if id == "" {
			return
		}
		sendPacket(Packet{
			Act: "SCREENSHOT",
			Data: map[string]interface{}{
				"device": id,
				"bridge": generateEventID(),
			},
		})

	case "processes":
		id := getDeviceID(parts)
		if id == "" {
			return
		}
		sendPacket(Packet{
			Act: "PROCESSES_LIST",
			Data: map[string]interface{}{
				"device": id,
			},
		})

	case "files":
		id := getDeviceID(parts)
		if id == "" {
			return
		}
		path := "/"
		if len(parts) > 2 {
			path = parts[2]
		}
		sendPacket(Packet{
			Act: "FILES_LIST",
			Data: map[string]interface{}{
				"device": id,
				"path":   path,
			},
		})

	case "ping":
		id := getDeviceID(parts)
		if id == "" {
			return
		}
		sendPacket(Packet{
			Act: "PING",
			Data: map[string]interface{}{
				"device": id,
			},
		})

	case "raw":
		if len(parts) < 2 {
			fmt.Println("Usage: raw <json>")
			return
		}
		jsonStr := strings.Join(parts[1:], " ")
		var pack Packet
		if err := json.Unmarshal([]byte(jsonStr), &pack); err != nil {
			fmt.Printf("Invalid JSON: %v\n", err)
			return
		}
		sendPacket(pack)

	// Mock desktop specific commands
	case "resolution":
		if mockDesktopMode {
			handleMockDesktopCommand(input)
		} else {
			fmt.Println("Command only available in mock-desktop mode")
		}

	case "pong":
		if mockDesktopMode {
			handleMockDesktopCommand(input)
		} else {
			fmt.Println("Command only available in mock-desktop mode")
		}

	case "stats":
		if mockDesktopMode {
			handleMockDesktopCommand(input)
		} else {
			fmt.Println("Command only available in mock-desktop mode")
		}

	default:
		fmt.Printf("Unknown command: %s\n", cmd)
	}
}

func getDeviceID(parts []string) string {
	if len(parts) > 1 {
		return parts[1]
	}
	if deviceID != "" {
		return deviceID
	}
	fmt.Println("No device ID specified and no default device set.")
	fmt.Println("Usage: <command> <device_id>")
	return ""
}

func generateEventID() string {
	id := make([]byte, 16)
	now := time.Now().UnixNano()
	for i := range id {
		id[i] = byte(now>>(i*4)) ^ byte(i*31+13)
	}
	return hex.EncodeToString(id)
}

func sendPacket(pack Packet) {
	data, err := json.Marshal(pack)
	if err != nil {
		fmt.Printf("Failed to marshal packet: %v\n", err)
		return
	}

	connMutex.Lock()
	err = conn.WriteMessage(websocket.BinaryMessage, data)
	connMutex.Unlock()

	if err != nil {
		fmt.Printf("Failed to send packet: %v\n", err)
		return
	}

	fmt.Printf("[SENT] %s\n", string(data))
}

// streamEncrypt encrypts data using AES-256-CTR with the session secret
// Matches utils.StreamEncrypt in the Spark codebase
func streamEncrypt(data, key []byte) []byte {
	if len(key) < 32 {
		// Fallback to XOR if key is too short
		return xorBytes(data, key)
	}

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return xorBytes(data, key)
	}

	// Derive IV from key (last 16 bytes or XOR of key bytes)
	iv := make([]byte, 16)
	if len(key) >= 48 {
		copy(iv, key[32:48])
	} else {
		// Derive IV by XORing key bytes
		for i := 0; i < len(key); i++ {
			iv[i%16] ^= key[i]
		}
	}

	stream := cipher.NewCTR(block, iv)
	result := make([]byte, len(data))
	stream.XORKeyStream(result, data)

	return result
}

// streamDecrypt decrypts data using AES-256-CTR with the session secret
func streamDecrypt(data, key []byte) []byte {
	// CTR mode is symmetric
	return streamEncrypt(data, key)
}

func xorBytes(data, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// ============================================================================
// Mock Desktop Functions (for E2E testing)
// ============================================================================

// Protocol constants (must match client/service/desktop/desktop.go)
const (
	magicDesktop   = "\x22\x16\x13\x11" // 34, 22, 19, 17
	serviceDesktop = 20
	serviceShare   = 21

	opFrameFirst    = 0 // First chunk of frame
	opFrameContinue = 1 // Continuation chunk
	opResolution    = 2 // Resolution update
	opJSON          = 3 // JSON control message

	// Protocol v2 adds 8 bytes of per-frame metadata after the event ID.
	eventIDLength           = 16
	frameMetaLength         = 8
	legacyFrameHeaderLength = 4 + 1 + 1 + eventIDLength
	frameHeaderLength       = legacyFrameHeaderLength + frameMetaLength
)

// runMockDesktop starts the mock desktop streaming loop
func runMockDesktop() {
	fmt.Println("[MockDesktop] Starting mock desktop stream...")

	// Start frame loop
	ticker := time.NewTicker(time.Second / time.Duration(mockDesktopFPS))
	defer ticker.Stop()

	lastDesktopHex := ""
	for range ticker.C {
		if conn == nil {
			return
		}

		eventID, desktopHex, ok := getMockDesktopSession()
		if !ok {
			continue
		}

		// On new desktop sessions, send a resolution packet so the browser sizes the canvas.
		if desktopHex != lastDesktopHex {
			lastDesktopHex = desktopHex
			sendMockResolution(eventID, mockDesktopWidth, mockDesktopHeight)
		}

		mockFrameCount++
		sendMockFrame(eventID)

		// Log every 30 frames
		if mockFrameCount%30 == 0 {
			fmt.Printf("[MockDesktop] Sent %d frames\n", mockFrameCount)
		}
	}
}

// sendMockResolution sends a binary resolution packet
func sendMockResolution(eventID []byte, width, height int) {
	// Format (v2): magic(4) + service(1) + op(1) + eventID(16) + frameMeta(8) + bodyLen(2) + width(2) + height(2)
	buf := make([]byte, frameHeaderLength+2+2+2)
	offset := 0

	// Magic prefix
	copy(buf[offset:], magicDesktop)
	offset += 4

	// Service and op
	buf[offset] = serviceDesktop
	offset++
	buf[offset] = opResolution
	offset++

	// Event ID (desktop session id)
	copy(buf[offset:], eventID[:16])
	offset += 16

	// Frame metadata (frameSeq=0 marks non-frame payloads like resolution updates)
	binary.BigEndian.PutUint32(buf[offset:], 0)
	binary.BigEndian.PutUint16(buf[offset+4:], 0)
	binary.BigEndian.PutUint16(buf[offset+6:], 1)
	offset += 8

	// Body length (4 bytes: width + height)
	binary.BigEndian.PutUint16(buf[offset:], 4)
	offset += 2

	// Width and height
	binary.BigEndian.PutUint16(buf[offset:], uint16(width))
	offset += 2
	binary.BigEndian.PutUint16(buf[offset:], uint16(height))

	connMutex.Lock()
	err := conn.WriteMessage(websocket.BinaryMessage, buf)
	connMutex.Unlock()

	if err != nil {
		fmt.Printf("[MockDesktop] Failed to send resolution: %v\n", err)
		return
	}
	fmt.Printf("[MockDesktop] Sent resolution: %dx%d\n", width, height)
}

// sendMockDesktopInit sends a JSON DESKTOP_INIT packet
func sendMockDesktopInit() {
	pack := Packet{
		Act: "DESKTOP_INIT",
		Data: map[string]interface{}{
			"width":  mockDesktopWidth,
			"height": mockDesktopHeight,
			"monitors": []map[string]interface{}{
				{
					"id":     0,
					"name":   "MockDisplay",
					"width":  mockDesktopWidth,
					"height": mockDesktopHeight,
				},
			},
		},
	}

	jsonBytes, _ := json.Marshal(pack)
	sendJSONPacket(jsonBytes)
	fmt.Println("[MockDesktop] Sent DESKTOP_INIT")
}

// sendJSONPacket sends a JSON packet with the desktop protocol header
func sendJSONPacket(jsonBytes []byte) {
	// Format: magic(4) + service(1) + op(1) + bodyLen(2) + body
	buf := make([]byte, 4+1+1+2+len(jsonBytes))
	offset := 0

	copy(buf[offset:], magicDesktop)
	offset += 4

	buf[offset] = serviceDesktop
	offset++
	buf[offset] = opJSON
	offset++

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(jsonBytes)))
	offset += 2

	copy(buf[offset:], jsonBytes)

	connMutex.Lock()
	err := conn.WriteMessage(websocket.BinaryMessage, buf)
	connMutex.Unlock()

	if err != nil {
		fmt.Printf("[MockDesktop] Failed to send JSON packet: %v\n", err)
	}
}

// sendMockFrame sends a mock desktop frame with a simple test pattern
func sendMockFrame(eventID []byte) {
	// Generate a small test image block
	blockWidth := 100
	blockHeight := 100
	blockX := int(mockFrameCount*10) % (mockDesktopWidth - blockWidth)
	blockY := int(mockFrameCount*7) % (mockDesktopHeight - blockHeight)

	// Create test image with varying color
	img := image.NewRGBA(image.Rect(0, 0, blockWidth, blockHeight))
	r := uint8((mockFrameCount * 3) % 256)
	g := uint8((mockFrameCount * 5) % 256)
	b := uint8((mockFrameCount * 7) % 256)
	for y := 0; y < blockHeight; y++ {
		for x := 0; x < blockWidth; x++ {
			img.Set(x, y, color.RGBA{r, g, b, 255})
		}
	}

	// Encode as JPEG
	var jpegBuf bytes.Buffer
	jpeg.Encode(&jpegBuf, img, &jpeg.Options{Quality: 70})
	jpegBytes := jpegBuf.Bytes()

	// Build frame packet
	// Block format: bodyLen(2) + imageType(2) + x(2) + y(2) + w(2) + h(2) + imageData
	blockBodyLen := 10 + len(jpegBytes)
	blockBuf := make([]byte, 2+blockBodyLen)
	blockOffset := 0

	binary.BigEndian.PutUint16(blockBuf[blockOffset:], uint16(blockBodyLen))
	blockOffset += 2
	binary.BigEndian.PutUint16(blockBuf[blockOffset:], 1) // JPEG = 1
	blockOffset += 2
	binary.BigEndian.PutUint16(blockBuf[blockOffset:], uint16(blockX))
	blockOffset += 2
	binary.BigEndian.PutUint16(blockBuf[blockOffset:], uint16(blockY))
	blockOffset += 2
	binary.BigEndian.PutUint16(blockBuf[blockOffset:], uint16(blockWidth))
	blockOffset += 2
	binary.BigEndian.PutUint16(blockBuf[blockOffset:], uint16(blockHeight))
	blockOffset += 2
	copy(blockBuf[blockOffset:], jpegBytes)

	connMutex.Lock()
	mockWireFrameSeq++
	frameSeq := mockWireFrameSeq

	// Frame header: magic(4) + service(1) + op(1) + eventID(16) + blocks
	frameBuf := make([]byte, frameHeaderLength+len(blockBuf))
	offset := 0

	copy(frameBuf[offset:], magicDesktop)
	offset += 4
	frameBuf[offset] = serviceDesktop
	offset++
	frameBuf[offset] = opFrameFirst
	offset++

	copy(frameBuf[offset:], eventID[:16])
	offset += 16

	binary.BigEndian.PutUint32(frameBuf[offset:], frameSeq)
	binary.BigEndian.PutUint16(frameBuf[offset+4:], 0)
	binary.BigEndian.PutUint16(frameBuf[offset+6:], 1)
	offset += 8

	copy(frameBuf[offset:], blockBuf)

	err := conn.WriteMessage(websocket.BinaryMessage, frameBuf)
	connMutex.Unlock()

	if err != nil {
		fmt.Printf("[MockDesktop] Failed to send frame: %v\n", err)
	}
}

// generateEventIDBytes generates a 16-byte event ID
func generateEventIDBytes() []byte {
	id := make([]byte, 16)
	now := time.Now().UnixNano()
	for i := range id {
		id[i] = byte(now>>(i*4)) ^ byte(i*31+13)
	}
	return id
}

// sendMockFullFrame sends a complete frame covering the entire screen
// Used when DESKTOP_SHOT is requested to ensure the browser gets a full initial frame
func sendMockFullFrame(eventID []byte) {
	// Create a full-screen gradient image
	img := image.NewRGBA(image.Rect(0, 0, mockDesktopWidth, mockDesktopHeight))
	for y := 0; y < mockDesktopHeight; y++ {
		for x := 0; x < mockDesktopWidth; x++ {
			r := uint8(x * 255 / mockDesktopWidth)
			g := uint8(y * 255 / mockDesktopHeight)
			b := uint8(128)
			img.Set(x, y, color.RGBA{r, g, b, 255})
		}
	}

	// Encode as JPEG with higher quality for full frames
	var jpegBuf bytes.Buffer
	jpeg.Encode(&jpegBuf, img, &jpeg.Options{Quality: 80})
	jpegBytes := jpegBuf.Bytes()

	// Build full frame packet
	blockBodyLen := 10 + len(jpegBytes)
	blockBuf := make([]byte, 2+blockBodyLen)
	blockOffset := 0

	binary.BigEndian.PutUint16(blockBuf[blockOffset:], uint16(blockBodyLen))
	blockOffset += 2
	binary.BigEndian.PutUint16(blockBuf[blockOffset:], 1) // JPEG = 1
	blockOffset += 2
	binary.BigEndian.PutUint16(blockBuf[blockOffset:], 0) // x = 0
	blockOffset += 2
	binary.BigEndian.PutUint16(blockBuf[blockOffset:], 0) // y = 0
	blockOffset += 2
	binary.BigEndian.PutUint16(blockBuf[blockOffset:], uint16(mockDesktopWidth))
	blockOffset += 2
	binary.BigEndian.PutUint16(blockBuf[blockOffset:], uint16(mockDesktopHeight))
	blockOffset += 2
	copy(blockBuf[blockOffset:], jpegBytes)

	connMutex.Lock()
	mockWireFrameSeq++
	frameSeq := mockWireFrameSeq

	// Frame header (v2)
	frameBuf := make([]byte, frameHeaderLength+len(blockBuf))
	offset := 0

	copy(frameBuf[offset:], magicDesktop)
	offset += 4
	frameBuf[offset] = serviceDesktop
	offset++
	frameBuf[offset] = opFrameFirst
	offset++

	copy(frameBuf[offset:], eventID[:16])
	offset += 16

	binary.BigEndian.PutUint32(frameBuf[offset:], frameSeq)
	binary.BigEndian.PutUint16(frameBuf[offset+4:], 0)
	binary.BigEndian.PutUint16(frameBuf[offset+6:], 1)
	offset += 8

	copy(frameBuf[offset:], blockBuf)

	err := conn.WriteMessage(websocket.BinaryMessage, frameBuf)
	connMutex.Unlock()

	if err != nil {
		fmt.Printf("[MockDesktop] Failed to send full frame: %v\n", err)
	} else {
		fmt.Printf("[MockDesktop] Sent full frame (%dx%d, %d bytes)\n", mockDesktopWidth, mockDesktopHeight, len(frameBuf))
	}
}

// handleMockDesktopCommand handles stdin commands for mock desktop control
func handleMockDesktopCommand(cmd string) {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "resolution":
		if len(parts) >= 3 {
			var w, h int
			fmt.Sscanf(parts[1], "%d", &w)
			fmt.Sscanf(parts[2], "%d", &h)
			if w > 0 && h > 0 {
				mockDesktopWidth = w
				mockDesktopHeight = h
				if eventID, _, ok := getMockDesktopSession(); ok {
					sendMockResolution(eventID, w, h)
				} else {
					fmt.Println("[MockDesktop] No active desktop session")
				}
			}
		} else {
			fmt.Println("Usage: resolution <width> <height>")
		}
	case "pong":
		source := "device"
		if len(parts) >= 2 {
			source = parts[1]
		}
		if _, desktopHex, ok := getMockDesktopSession(); ok {
			sendPacket(Packet{
				Act:   "DESKTOP_PONG",
				Code:  0,
				Event: desktopHex,
				Data: map[string]interface{}{
					"source": source,
				},
			})
			fmt.Printf("[MockDesktop] Sent PONG (source=%s)\n", source)
		} else {
			fmt.Println("[MockDesktop] No active desktop session")
		}
	case "stats":
		fmt.Printf("[MockDesktop] Frames sent: %d\n", mockFrameCount)
		fmt.Printf("[MockDesktop] Resolution: %dx%d @ %d FPS\n", mockDesktopWidth, mockDesktopHeight, mockDesktopFPS)
	}
}

func init() {
	// Seed random with something
	_ = bytes.Equal(nil, nil)
}
