package desktop

import (
	"Spark/server/config"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestIceCredentialIssuerMint(t *testing.T) {
	cfg := &config.WebRTCConfig{
		Enabled:       true,
		CredentialTTL: "2m",
		Servers: []config.WebRTCIceServer{
			{
				URLs:             []string{"turn:relay.example.com:3478?transport=tcp"},
				CredentialSecret: "secret",
				CredentialType:   "password",
			},
		},
		RelayHint: "turn",
	}
	issuer := newIceCredentialIssuer(cfg)
	if issuer == nil {
		t.Fatalf("expected issuer")
	}
	bundle, ok := issuer.mint("desk-123")
	if !ok {
		t.Fatalf("expected mint bundle")
	}
	if len(bundle.servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(bundle.servers))
	}
	entry := bundle.servers[0]
	username, _ := entry["username"].(string)
	if username == "" {
		t.Fatalf("expected minted username")
	}
	expectedUsername := fmt.Sprintf("%d:%s", bundle.expiresAt.Unix(), "desk-123")
	if username != expectedUsername {
		t.Fatalf("unexpected username: %s", username)
	}
	credential, _ := entry["credential"].(string)
	if credential == "" {
		t.Fatalf("expected credential")
	}
	if credential != turnCredentialHMAC(expectedUsername, "secret") {
		t.Fatalf("unexpected credential signature")
	}
	if bundle.relayHint != "turn" {
		t.Fatalf("expected relay hint to propagate")
	}
	if bundle.ttl < time.Minute {
		t.Fatalf("expected ttl to be parsed")
	}
}

func TestEnrichDesktopCapsWithMintedIce(t *testing.T) {
	prevIssuer := credentialIssuer
	defer func() {
		credentialIssuer = prevIssuer
	}()
	credentialIssuer = &iceCredentialIssuer{
		ttl:       time.Minute,
		relayHint: "turn",
		servers: []iceServerTemplate{
			{
				urls:           []string{"turn:relay"},
				credentialType: "password",
				secret:         "secret",
			},
		},
	}
	caps := map[string]any{}
	enriched := enrichDesktopWebRTCCaps("desk-456", caps)
	if enriched == nil {
		t.Fatalf("expected capabilities map")
	}
	webrtcCaps, ok := enriched["webrtc"].(map[string]any)
	if !ok {
		t.Fatalf("expected webrtc caps")
	}
	iceServers, ok := webrtcCaps["iceServers"].([]map[string]any)
	if !ok || len(iceServers) == 0 {
		t.Fatalf("expected ice servers injected")
	}
	token, _ := webrtcCaps["token"].(map[string]any)
	if token == nil {
		t.Fatalf("expected token metadata")
	}
	if _, ok := token["expiresAt"]; !ok {
		t.Fatalf("expected expiresAt field")
	}
	if _, ok := token["ttlSeconds"]; !ok {
		t.Fatalf("expected ttlSeconds")
	}
	cfg, _ := webrtcCaps["config"].(map[string]any)
	if cfg == nil {
		t.Fatalf("expected config block")
	}
	if reflect.ValueOf(cfg["iceServers"]).Pointer() == reflect.ValueOf(webrtcCaps["iceServers"]).Pointer() {
		t.Fatalf("iceServers slices should be distinct copies")
	}
	if webrtcCaps["relayHint"] != "turn" {
		t.Fatalf("expected relay hint to propagate")
	}
}
