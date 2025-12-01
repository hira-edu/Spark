//go:build ignore

// End-to-end test for Spark features
// Run from the spark directory: go run test_e2e.go
// This connects to the server and tests features on connected devices

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"time"
)

type Packet struct {
	Code int                    `json:"code"`
	Msg  string                 `json:"msg,omitempty"`
	Data map[string]interface{} `json:"data,omitempty"`
}

var client *http.Client
var baseURL = "http://localhost:8443"
var authToken string

func main() {
	// Create HTTP client with cookie jar
	jar, _ := cookiejar.New(nil)
	client = &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
	}

	fmt.Println("=== Spark End-to-End Test ===")
	fmt.Printf("Server: %s\n\n", baseURL)

	// Try to login first
	if !login() {
		fmt.Println("\nAuthentication required but failed.")
		fmt.Println("Attempting direct device list (may fail without auth)...")
	}

	// Get device list
	devices := getDevices()
	if len(devices) == 0 {
		fmt.Println("No devices connected!")
		os.Exit(1)
	}

	// Get first device
	var deviceID string
	var deviceInfo map[string]interface{}
	for id, info := range devices {
		deviceID = id
		deviceInfo = info.(map[string]interface{})
		break
	}

	fmt.Printf("Testing device: %s\n", deviceID[:16]+"...")
	if name, ok := deviceInfo["hostname"]; ok {
		fmt.Printf("Hostname: %v\n", name)
	}
	fmt.Println()

	// Test each feature
	testProcessList(deviceID)
	testFileList(deviceID)
	testWebcamList(deviceID)
	testAudioList(deviceID)

	fmt.Println("\n=== Tests Complete ===")
}

func login() bool {
	fmt.Println("Attempting login...")

	// Check if setup is needed
	resp, err := client.Get(baseURL + "/api/auth/setup/check")
	if err != nil {
		fmt.Printf("  Setup check failed: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	var setupResp Packet
	json.NewDecoder(resp.Body).Decode(&setupResp)

	if needsSetup, ok := setupResp.Data["needsSetup"].(bool); ok && needsSetup {
		fmt.Println("  Server needs initial setup - creating admin user...")
		// Create initial admin
		body, _ := json.Marshal(map[string]string{
			"username": "admin",
			"password": "admin123",
			"email":    "admin@test.local",
		})
		resp, err = client.Post(baseURL+"/api/auth/setup", "application/json", bytes.NewReader(body))
		if err != nil {
			fmt.Printf("  Setup failed: %v\n", err)
			return false
		}
		resp.Body.Close()
	}

	// Try to login
	body, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "admin123",
	})
	resp, err = client.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("  Login request failed: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	var loginResp Packet
	json.NewDecoder(resp.Body).Decode(&loginResp)

	if loginResp.Code != 0 {
		fmt.Printf("  Login failed: %s\n", loginResp.Msg)
		return false
	}

	// Get token from response
	if token, ok := loginResp.Data["token"].(string); ok {
		authToken = token
		fmt.Printf("  Logged in successfully (token: %s...)\n", token[:8])
		return true
	}

	fmt.Println("  Login response didn't include token")
	return false
}

func getDevices() map[string]interface{} {
	fmt.Println("Getting device list...")

	req, _ := http.NewRequest("POST", baseURL+"/api/device/list", nil)
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.AddCookie(&http.Cookie{Name: "Authorization", Value: authToken})
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("  Request failed: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result Packet
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Printf("  Parse failed: %v\n", err)
		return nil
	}

	if result.Code != 0 {
		fmt.Printf("  Failed: %s (code=%d)\n", result.Msg, result.Code)
		return nil
	}

	if result.Data == nil {
		fmt.Println("  No devices in response")
		return nil
	}

	fmt.Printf("  Found %d device(s)\n", len(result.Data))
	return result.Data
}

func testProcessList(deviceID string) {
	fmt.Println("\n--- Testing Process List ---")

	body, _ := json.Marshal(map[string]string{"device": deviceID})
	req, _ := http.NewRequest("POST", baseURL+"/api/device/process/list", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.AddCookie(&http.Cookie{Name: "Authorization", Value: authToken})
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("  [FAIL] Request error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var result Packet
	json.Unmarshal(respBody, &result)

	if result.Code == 0 {
		if procs, ok := result.Data["processes"].([]interface{}); ok {
			fmt.Printf("  [OK] Got %d processes\n", len(procs))
		} else {
			fmt.Println("  [OK] Process list returned")
		}
	} else {
		fmt.Printf("  [FAIL] %s (code=%d)\n", result.Msg, result.Code)
	}
}

func testFileList(deviceID string) {
	fmt.Println("\n--- Testing File List ---")

	body, _ := json.Marshal(map[string]string{
		"device": deviceID,
		"path":   "C:\\",
	})
	req, _ := http.NewRequest("POST", baseURL+"/api/device/file/list", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.AddCookie(&http.Cookie{Name: "Authorization", Value: authToken})
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("  [FAIL] Request error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var result Packet
	json.Unmarshal(respBody, &result)

	if result.Code == 0 {
		if files, ok := result.Data["files"].([]interface{}); ok {
			fmt.Printf("  [OK] Got %d files/folders\n", len(files))
		} else {
			fmt.Println("  [OK] File list returned")
		}
	} else {
		fmt.Printf("  [FAIL] %s (code=%d)\n", result.Msg, result.Code)
	}
}

func testWebcamList(deviceID string) {
	fmt.Println("\n--- Testing Webcam List ---")

	// The webcam list goes through the websocket handler, not a direct API
	// We need to use the terminal/desktop style websocket connection
	// For now, we'll test via the device call mechanism

	body, _ := json.Marshal(map[string]interface{}{
		"device": deviceID,
		"act":    "WEBCAM_LIST",
	})
	req, _ := http.NewRequest("POST", baseURL+"/api/device/webcam", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.AddCookie(&http.Cookie{Name: "Authorization", Value: authToken})
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("  [FAIL] Request error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Webcam is a websocket endpoint, HTTP will fail
	if resp.StatusCode == 400 {
		fmt.Println("  [INFO] Webcam requires WebSocket connection (expected)")
		fmt.Println("  [INFO] Webcam implementation: Windows VfW/DirectShow")
	} else {
		respBody, _ := io.ReadAll(resp.Body)
		var result Packet
		json.Unmarshal(respBody, &result)
		fmt.Printf("  Response: %+v\n", result)
	}
}

func testAudioList(deviceID string) {
	fmt.Println("\n--- Testing Audio List ---")

	body, _ := json.Marshal(map[string]interface{}{
		"device": deviceID,
		"act":    "AUDIO_LIST",
	})
	req, _ := http.NewRequest("POST", baseURL+"/api/device/audio", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.AddCookie(&http.Cookie{Name: "Authorization", Value: authToken})
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("  [FAIL] Request error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 400 {
		fmt.Println("  [INFO] Audio requires WebSocket connection (expected)")
		fmt.Println("  [INFO] Audio implementation: stubbed (requires PortAudio)")
	} else {
		respBody, _ := io.ReadAll(resp.Body)
		var result Packet
		json.Unmarshal(respBody, &result)
		fmt.Printf("  Response: %+v\n", result)
	}
}
