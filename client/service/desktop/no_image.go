package desktop

import "errors"

// IsNoImageError reports whether err indicates that no desktop frame is currently available.
// This is expected for backends like DXGI output duplication when the desktop hasn't changed yet.
func IsNoImageError(err error) bool {
	return errors.Is(err, errNoImage)
}
