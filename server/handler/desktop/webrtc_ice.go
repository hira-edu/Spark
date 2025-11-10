package desktop

import (
	"Spark/server/config"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const defaultWebRTCCredentialTTL = 10 * time.Minute

var credentialIssuer = newIceCredentialIssuer(config.Config.WebRTC)

type iceCredentialIssuer struct {
	ttl       time.Duration
	relayHint string
	servers   []iceServerTemplate
}

type iceServerTemplate struct {
	urls           []string
	username       string
	credential     string
	credentialType string
	secret         string
}

type mintedIceBundle struct {
	servers   []map[string]any
	issuedAt  time.Time
	expiresAt time.Time
	ttl       time.Duration
	relayHint string
}

func newIceCredentialIssuer(cfg *config.WebRTCConfig) *iceCredentialIssuer {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	if len(cfg.Servers) == 0 {
		return nil
	}
	ttl := parseCredentialTTL(cfg.CredentialTTL)
	relayHint := strings.TrimSpace(cfg.RelayHint)
	templates := make([]iceServerTemplate, 0, len(cfg.Servers))
	for _, srv := range cfg.Servers {
		if len(srv.URLs) == 0 {
			continue
		}
		urls := make([]string, 0, len(srv.URLs))
		for _, raw := range srv.URLs {
			if trimmed := strings.TrimSpace(raw); trimmed != "" {
				urls = append(urls, trimmed)
			}
		}
		if len(urls) == 0 {
			continue
		}
		template := iceServerTemplate{
			urls:           urls,
			username:       strings.TrimSpace(srv.Username),
			credential:     strings.TrimSpace(srv.Credential),
			credentialType: strings.TrimSpace(srv.CredentialType),
			secret:         strings.TrimSpace(srv.CredentialSecret),
		}
		templates = append(templates, template)
	}
	if len(templates) == 0 {
		return nil
	}
	return &iceCredentialIssuer{
		ttl:       ttl,
		relayHint: relayHint,
		servers:   templates,
	}
}

func parseCredentialTTL(raw string) time.Duration {
	if raw == "" {
		return defaultWebRTCCredentialTTL
	}
	if dur, err := time.ParseDuration(raw); err == nil && dur > 0 {
		return dur
	}
	if secs, err := strconv.ParseFloat(raw, 64); err == nil && secs > 0 {
		return time.Duration(secs * float64(time.Second))
	}
	return defaultWebRTCCredentialTTL
}

func (i *iceCredentialIssuer) mint(desktopID string) (mintedIceBundle, bool) {
	if i == nil || len(i.servers) == 0 || desktopID == "" {
		return mintedIceBundle{}, false
	}
	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(i.ttl)
	servers := make([]map[string]any, 0, len(i.servers))
	for _, tmpl := range i.servers {
		entry := tmpl.build(desktopID, expiresAt)
		if entry == nil {
			continue
		}
		servers = append(servers, entry)
	}
	if len(servers) == 0 {
		return mintedIceBundle{}, false
	}
	return mintedIceBundle{
		servers:   servers,
		issuedAt:  issuedAt,
		expiresAt: expiresAt,
		ttl:       i.ttl,
		relayHint: i.relayHint,
	}, true
}

func (t iceServerTemplate) build(desktopID string, expiresAt time.Time) map[string]any {
	if len(t.urls) == 0 {
		return nil
	}
	username := t.username
	credential := t.credential
	if t.secret != "" && desktopID != "" {
		username = fmt.Sprintf("%d:%s", expiresAt.Unix(), desktopID)
		credential = turnCredentialHMAC(username, t.secret)
	}
	entry := map[string]any{
		"urls": append([]string(nil), t.urls...),
	}
	if username != "" {
		entry["username"] = username
	}
	if credential != "" {
		entry["credential"] = credential
	}
	if t.credentialType != "" {
		entry["credentialType"] = t.credentialType
	}
	return entry
}

func turnCredentialHMAC(username, secret string) string {
	if username == "" || secret == "" {
		return ""
	}
	h := hmac.New(sha1.New, []byte(secret))
	_, _ = h.Write([]byte(username))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func enrichDesktopWebRTCCaps(desktopID string, caps map[string]any) map[string]any {
	bundle, ok := credentialIssuer.mint(desktopID)
	if !ok {
		return caps
	}
	if caps == nil {
		caps = make(map[string]any)
	}
	webrtcCaps, _ := mapFromAny(caps["webrtc"])
	if webrtcCaps == nil {
		webrtcCaps = map[string]any{}
		caps["webrtc"] = webrtcCaps
	}
	ice := cloneIceServers(bundle.servers)
	webrtcCaps["iceServers"] = ice
	webrtcCaps["config"] = map[string]any{
		"iceServers": cloneIceServers(bundle.servers),
	}
	token := map[string]any{
		"issuedAt":    bundle.issuedAt.Unix(),
		"issuedAtMs":  bundle.issuedAt.UnixMilli(),
		"expiresAt":   bundle.expiresAt.Unix(),
		"expiresAtMs": bundle.expiresAt.UnixMilli(),
		"ttlSeconds":  int64(bundle.ttl / time.Second),
	}
	webrtcCaps["token"] = token
	webrtcCaps["ttlSeconds"] = int64(bundle.ttl / time.Second)
	if bundle.relayHint != "" {
		webrtcCaps["relayHint"] = bundle.relayHint
	}
	return caps
}

func cloneIceServers(src []map[string]any) []map[string]any {
	if len(src) == 0 {
		return nil
	}
	dst := make([]map[string]any, 0, len(src))
	for _, entry := range src {
		if len(entry) == 0 {
			continue
		}
		copyEntry := make(map[string]any, len(entry))
		for k, v := range entry {
			switch val := v.(type) {
			case []string:
				copyEntry[k] = append([]string(nil), val...)
			default:
				copyEntry[k] = val
			}
		}
		dst = append(dst, copyEntry)
	}
	return dst
}
