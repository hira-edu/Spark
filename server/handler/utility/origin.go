package utility

import (
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// ValidateWebSocketOrigin checks if the request Origin matches the host (including forwarded hosts)
// If requireOrigin is true, requests without an Origin header are rejected.
func ValidateWebSocketOrigin(ctx *gin.Context, requireOrigin bool) bool {
	origin := strings.TrimSpace(ctx.GetHeader("Origin"))
	if origin == "" {
		return !requireOrigin
	}

	originURL, err := url.Parse(origin)
	if err != nil || originURL.Host == "" {
		return false
	}
	originHost := stripPort(originURL.Host)
	if originHost == "" {
		return false
	}

	for _, candidate := range candidateHosts(ctx) {
		normalized := stripPort(candidate)
		if normalized == "" {
			continue
		}
		if strings.EqualFold(normalized, originHost) {
			return true
		}
		if isLocalhost(normalized) && isLocalhost(originHost) {
			return true
		}
	}

	return false
}

func candidateHosts(ctx *gin.Context) []string {
	var hosts []string

	if host := strings.TrimSpace(ctx.Request.Host); host != "" {
		hosts = append(hosts, host)
	}
	hosts = append(hosts, parseForwardList(ctx.GetHeader("X-Forwarded-Host"))...)
	hosts = append(hosts, parseForwardList(ctx.GetHeader("X-Original-Host"))...)
	hosts = append(hosts, parseForwardHeader(ctx.GetHeader("Forwarded"))...)

	return hosts
}

func parseForwardList(headerVal string) []string {
	if headerVal == "" {
		return nil
	}
	parts := strings.Split(headerVal, ",")
	results := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			results = append(results, part)
		}
	}
	return results
}

func parseForwardHeader(headerVal string) []string {
	if headerVal == "" {
		return nil
	}
	var hosts []string
	entries := strings.Split(headerVal, ",")
	for _, entry := range entries {
		pairs := strings.Split(entry, ";")
		for _, pair := range pairs {
			pair = strings.TrimSpace(pair)
			if len(pair) < 5 {
				continue
			}
			if strings.EqualFold(pair[:5], "host=") {
				host := strings.TrimSpace(pair[5:])
				host = strings.Trim(host, `"`)
				if host != "" {
					hosts = append(hosts, host)
				}
			}
		}
	}
	return hosts
}

func stripPort(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") {
		if idx := strings.LastIndex(host, "]"); idx != -1 {
			return host[1:idx]
		}
		return strings.Trim(host, "[]")
	}
	if strings.Count(host, ":") > 1 {
		return host
	}
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}
	return host
}

func isLocalhost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	default:
		return false
	}
}
