//go:build cgo && vpx

package desktop

// isVPXAvailable returns true when libvpx is available for VP8/VP9 encoding.
// This file is only compiled when CGO and the vpx build tag are enabled.
func isVPXAvailable() bool {
	return true
}
