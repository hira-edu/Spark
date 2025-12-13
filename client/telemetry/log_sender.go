package telemetry

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// SendLogsToServer sends buffered logs to the server's /api/client/logs/upload endpoint
func SendLogsToServer(serverURL, secret string, logs []LogEntry) error {
	if len(logs) == 0 {
		return nil
	}

	// Serialize logs to JSON
	data, err := json.Marshal(logs)
	if err != nil {
		return fmt.Errorf("marshal logs: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", serverURL+"/api/client/logs/upload", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Secret", secret)

	// Extract hostname from serverURL for SNI
	var serverName string
	if u, err := url.Parse(serverURL); err == nil && u.Hostname() != "" {
		serverName = u.Hostname()
	}

	// Send request with timeout (accept self-signed certs)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         serverName, // Required for SNI when connecting via IP
				InsecureSkipVerify: true,       // Accept self-signed certificates
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Read error response
		body := make([]byte, 512)
		n, _ := resp.Body.Read(body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body[:n]))
	}

	return nil
}
