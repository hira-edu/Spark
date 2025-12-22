//go:build !cgo || !vpx

package desktop

// isVPXAvailable returns false when libvpx is not available.
// To enable VP8/VP9 support, build with: go build -tags "cgo,vpx"
func isVPXAvailable() bool {
	return false
}
