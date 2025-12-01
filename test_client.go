//go:build ignore

package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

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

func main() {
	host := flag.String("host", "localhost", "Server host")
	port := flag.Int("port", 8443, "Server port")
	salt := flag.String("salt", "testsalt1234567890123", "Server salt (must match config.json)")
	secure := flag.Bool("secure", false, "Use wss:// instead of ws://")
	flag.Parse()

	fmt.Println("=== Spark WebSocket Test Client ===")
	fmt.Printf("Connecting to %s:%d (secure=%v)\n", *host, *port, *secure)

	// Generate credentials
	uuid, key := generateCredentials(*salt)
	fmt.Printf("Generated UUID: %s\n", hex.EncodeToString(uuid))
	fmt.Printf("Generated Key: %s\n", hex.EncodeToString(key))

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

	var err error
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
	fmt.Println("Connected successfully!\n")

	// Start message reader
	go readMessages()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

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
			fmt.Printf("\n[BINARY] Service=%d Op=%d Len=%d\n", service, op, len(data))
			continue
		}

		// Decrypt JSON packet
		decrypted := streamDecrypt(data, secret)
		var pack Packet
		if err := json.Unmarshal(decrypted, &pack); err != nil {
			fmt.Printf("\n[RAW] %s\n", string(decrypted))
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
	}
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

	encrypted := streamEncrypt(data, secret)

	connMutex.Lock()
	err = conn.WriteMessage(websocket.BinaryMessage, encrypted)
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

func init() {
	// Seed random with something
	_ = bytes.Equal(nil, nil)
}
