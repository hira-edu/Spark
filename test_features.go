//go:build ignore

package main

import (
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
	"strings"
	"sync"
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
	results   = make(chan Packet, 100)
)

func main() {
	host := flag.String("host", "localhost", "Server host")
	port := flag.Int("port", 8443, "Server port")
	salt := flag.String("salt", "testsalt1234567890123", "Server salt")
	test := flag.String("test", "all", "Test to run: webcam, terminal, desktop, files, processes, all")
	flag.Parse()

	fmt.Println("=== Spark Feature Test ===")
	fmt.Printf("Connecting to %s:%d\n", *host, *port)

	// Generate credentials and connect
	uuid, key := generateCredentials(*salt)
	url := fmt.Sprintf("ws://%s:%d/ws", *host, *port)

	headers := http.Header{}
	headers.Add("UUID", hex.EncodeToString(uuid))
	headers.Add("Key", hex.EncodeToString(key))

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	var err error
	var resp *http.Response
	conn, resp, err = dialer.Dial(url, headers)
	if err != nil {
		fmt.Printf("Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	secretHex := resp.Header.Get("Secret")
	secret, _ = hex.DecodeString(secretHex)
	fmt.Printf("Connected! Secret: %d bytes\n\n", len(secret))

	// Start message reader
	go readMessages()

	// Wait for device registration (DEVICE_UPDATE)
	fmt.Println("Waiting for device registration...")
	timeout := time.After(10 * time.Second)
	for deviceID == "" {
		select {
		case <-timeout:
			fmt.Println("Timeout waiting for device registration")
			os.Exit(1)
		case <-time.After(100 * time.Millisecond):
		}
	}
	fmt.Printf("Device registered: %s\n\n", deviceID[:16]+"...")

	// Run tests
	switch *test {
	case "webcam":
		testWebcam()
	case "terminal":
		testTerminal()
	case "desktop":
		testDesktop()
	case "files":
		testFiles()
	case "processes":
		testProcesses()
	case "all":
		testProcesses()
		testFiles()
		testWebcam()
		testTerminal()
		testDesktop()
	default:
		fmt.Printf("Unknown test: %s\n", *test)
	}

	fmt.Println("\n=== Tests Complete ===")
}

func testWebcam() {
	fmt.Println("--- Testing Webcam ---")

	// List webcams
	sendAndWait(Packet{Act: "WEBCAM_LIST"}, "WEBCAM_LIST", 5*time.Second)
}

func testTerminal() {
	fmt.Println("--- Testing Terminal ---")

	terminalID := generateEventID()

	// Initialize terminal
	resp := sendAndWait(Packet{
		Act:   "TERMINAL_INIT",
		Event: terminalID,
		Data: map[string]interface{}{
			"terminal": terminalID,
		},
	}, "TERMINAL_INIT", 5*time.Second)

	if resp.Code == 0 {
		fmt.Println("Terminal initialized successfully!")
		// Kill terminal
		time.Sleep(1 * time.Second)
		send(Packet{
			Act:   "TERMINAL_KILL",
			Event: terminalID,
			Data: map[string]interface{}{
				"terminal": terminalID,
			},
		})
	}
}

func testDesktop() {
	fmt.Println("--- Testing Desktop ---")

	desktopID := generateEventID()

	// Initialize desktop
	resp := sendAndWait(Packet{
		Act:   "DESKTOP_INIT",
		Event: desktopID,
		Data: map[string]interface{}{
			"desktop": desktopID,
		},
	}, "DESKTOP_INIT", 5*time.Second)

	if resp.Code == 0 {
		fmt.Println("Desktop initialized successfully!")
		// Wait for frames
		time.Sleep(2 * time.Second)
		// Kill desktop
		send(Packet{
			Act:   "DESKTOP_KILL",
			Event: desktopID,
			Data: map[string]interface{}{
				"desktop": desktopID,
			},
		})
	}
}

func testFiles() {
	fmt.Println("--- Testing Files ---")

	// List files in root
	sendAndWait(Packet{
		Act: "FILES_LIST",
		Data: map[string]interface{}{
			"path": "C:\\",
		},
	}, "FILES_LIST", 5*time.Second)
}

func testProcesses() {
	fmt.Println("--- Testing Processes ---")

	sendAndWait(Packet{Act: "PROCESSES_LIST"}, "PROCESSES_LIST", 5*time.Second)
}

func sendAndWait(pack Packet, expectedAct string, timeout time.Duration) Packet {
	send(pack)

	timer := time.After(timeout)
	for {
		select {
		case resp := <-results:
			if resp.Act == expectedAct || (resp.Act == "" && resp.Code != 0) {
				if resp.Code == 0 {
					fmt.Printf("  [OK] %s succeeded\n", expectedAct)
				} else {
					fmt.Printf("  [FAIL] %s failed: %s (code=%d)\n", expectedAct, resp.Msg, resp.Code)
				}
				if resp.Data != nil {
					// Print summary of data
					for k, v := range resp.Data {
						switch val := v.(type) {
						case []interface{}:
							fmt.Printf("       %s: %d items\n", k, len(val))
						case string:
							if len(val) > 50 {
								fmt.Printf("       %s: %s...\n", k, val[:50])
							} else {
								fmt.Printf("       %s: %s\n", k, val)
							}
						default:
							fmt.Printf("       %s: %v\n", k, v)
						}
					}
				}
				return resp
			}
		case <-timer:
			fmt.Printf("  [TIMEOUT] %s timed out\n", expectedAct)
			return Packet{Code: -1, Msg: "timeout"}
		}
	}
}

func send(pack Packet) {
	data, _ := json.Marshal(pack)
	encrypted := streamEncrypt(data, secret)

	connMutex.Lock()
	conn.WriteMessage(websocket.BinaryMessage, encrypted)
	connMutex.Unlock()

	fmt.Printf("  Sent: %s\n", pack.Act)
}

func readMessages() {
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}

		// Check if binary packet (frame data)
		if len(data) > 5 && data[0] == 34 && data[1] == 22 && data[2] == 19 && data[3] == 17 {
			service := data[4]
			fmt.Printf("  [BINARY] Service=%d Len=%d bytes\n", service, len(data))
			continue
		}

		decrypted := streamDecrypt(data, secret)
		var pack Packet
		if err := json.Unmarshal(decrypted, &pack); err != nil {
			continue
		}

		// Handle device registration
		if pack.Act == "PING" {
			// Respond to ping
			send(Packet{Act: "PING", Code: 0, Event: pack.Event})
			continue
		}

		if pack.Data != nil {
			if id, ok := pack.Data["id"].(string); ok && deviceID == "" {
				deviceID = id
			}
		}

		// Queue result
		select {
		case results <- pack:
		default:
		}
	}
}

func generateCredentials(salt string) ([]byte, []byte) {
	uuid := make([]byte, 16)
	now := time.Now().UnixNano()
	for i := range uuid {
		uuid[i] = byte(now>>(i*4)) ^ byte(i*17+42)
	}

	saltBytes := []byte(salt)
	padding := make([]byte, 24)
	for i := range padding {
		padding[i] = 25
	}
	saltBytes = append(saltBytes, padding...)
	saltBytes = saltBytes[:24]

	hash := md5.Sum(uuid)
	block, _ := aes.NewCipher(saltBytes)
	stream := cipher.NewCTR(block, hash[:])
	encrypted := make([]byte, len(uuid))
	stream.XORKeyStream(encrypted, uuid)

	key := append(hash[:], encrypted...)
	return uuid, key
}

func generateEventID() string {
	id := make([]byte, 16)
	now := time.Now().UnixNano()
	for i := range id {
		id[i] = byte(now>>(i*4)) ^ byte(i*31+13)
	}
	return hex.EncodeToString(id)
}

func streamEncrypt(data, key []byte) []byte {
	if len(key) < 32 {
		return xorBytes(data, key)
	}

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return xorBytes(data, key)
	}

	iv := make([]byte, 16)
	for i := 0; i < len(key); i++ {
		iv[i%16] ^= key[i]
	}

	stream := cipher.NewCTR(block, iv)
	result := make([]byte, len(data))
	stream.XORKeyStream(result, data)
	return result
}

func streamDecrypt(data, key []byte) []byte {
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
	_ = bytes.Equal(nil, nil)
	_ = strings.Contains("", "")
}
