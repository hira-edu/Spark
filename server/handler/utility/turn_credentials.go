// Package utility provides TURN ephemeral credential generation per RFC 8656.
//
// This implements the "TURN REST API" pattern where credentials are time-limited
// and verified via HMAC rather than stored in a database. This is the recommended
// approach for production TURN servers like coturn with `use-auth-secret` mode.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8656
// Coturn docs: https://github.com/coturn/coturn/wiki/turnserver#turn-rest-api
package utility

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"time"
)

// TURNConfig holds the configuration for TURN credential generation.
type TURNConfig struct {
	// SharedSecret is the static-auth-secret from coturn config
	SharedSecret string

	// TTLSeconds is the credential validity period (default 3600)
	TTLSeconds int

	// ServerURIs are the TURN server URIs (e.g., "turn:example.com:3478")
	ServerURIs []string
}

// TURNCredentials represents ephemeral TURN credentials.
type TURNCredentials struct {
	// Username in RFC 8656 format: "<timestamp>:<identifier>"
	Username string `json:"username"`

	// Password is HMAC-SHA1(secret, username) base64 encoded
	Password string `json:"password"`

	// TTLSeconds is the credential lifetime in seconds
	TTLSeconds int `json:"ttl"`

	// Expiry is the Unix timestamp when credentials expire
	Expiry int64 `json:"expiry"`
}

// GenerateTURNCredentials creates time-limited credentials for TURN authentication.
//
// Parameters:
//   - config: TURN configuration with shared secret and TTL
//   - identifier: User identifier (e.g., session ID, device UUID)
//
// Returns credentials that coturn will validate using:
//
//	username = <timestamp>:<identifier>
//	password = base64(HMAC-SHA1(secret, username))
//
// The TURN server validates by:
//  1. Parsing timestamp from username
//  2. Checking if current_time < timestamp (not expired)
//  3. Computing expected password and comparing
//
// Returns nil if the shared secret is empty.
func GenerateTURNCredentials(config TURNConfig, identifier string) *TURNCredentials {
	if config.SharedSecret == "" {
		return nil
	}

	ttlSeconds := config.TTLSeconds
	if ttlSeconds <= 0 {
		ttlSeconds = 3600 // Default: 1 hour
	}

	// Expiry timestamp (Unix seconds)
	expiry := time.Now().Unix() + int64(ttlSeconds)

	// RFC 8656 format: "<timestamp>:<identifier>"
	username := fmt.Sprintf("%d:%s", expiry, identifier)

	// HMAC-SHA1 of the username using the shared secret
	mac := hmac.New(sha1.New, []byte(config.SharedSecret))
	mac.Write([]byte(username))
	password := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return &TURNCredentials{
		Username:   username,
		Password:   password,
		TTLSeconds: ttlSeconds,
		Expiry:     expiry,
	}
}

// TURNURIWithCredentials represents a TURN URI with embedded credentials.
type TURNURIWithCredentials struct {
	URL        string `json:"url"`
	Username   string `json:"username"`
	Credential string `json:"credential"`
}

// FormatTURNURIsWithCredentials formats TURN URIs with credentials for browser consumption.
// Returns a list of objects suitable for RTCPeerConnection iceServers configuration.
func FormatTURNURIsWithCredentials(uris []string, creds *TURNCredentials) []TURNURIWithCredentials {
	if creds == nil || len(uris) == 0 {
		return nil
	}

	result := make([]TURNURIWithCredentials, len(uris))
	for i, uri := range uris {
		result[i] = TURNURIWithCredentials{
			URL:        uri,
			Username:   creds.Username,
			Credential: creds.Password,
		}
	}
	return result
}

// ICEServerConfig represents a configured ICE server with optional credentials.
type ICEServerConfig struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// BuildICEServers constructs the ICE server configuration with ephemeral credentials.
//
// Parameters:
//   - stunServers: List of STUN server URIs (no credentials needed)
//   - turnServers: List of TURN server URIs
//   - secret: Shared secret for credential generation (empty = no auth)
//   - identifier: User/session identifier for credential username
//   - ttlSeconds: Credential validity period
//
// Returns a list of ICE server configs suitable for WebRTC PeerConnection.
func BuildICEServers(stunServers, turnServers []string, secret, identifier string, ttlSeconds int) []ICEServerConfig {
	var servers []ICEServerConfig

	// STUN servers don't require authentication
	if len(stunServers) > 0 {
		servers = append(servers, ICEServerConfig{
			URLs: stunServers,
		})
	}

	// TURN servers with ephemeral credentials (if secret is configured)
	if len(turnServers) > 0 {
		turnConfig := ICEServerConfig{
			URLs: turnServers,
		}

		// Only add credentials if secret is configured
		if secret != "" {
			config := TURNConfig{
				SharedSecret: secret,
				TTLSeconds:   ttlSeconds,
				ServerURIs:   turnServers,
			}
			if creds := GenerateTURNCredentials(config, identifier); creds != nil {
				turnConfig.Username = creds.Username
				turnConfig.Credential = creds.Password
			}
		}

		servers = append(servers, turnConfig)
	}

	return servers
}
