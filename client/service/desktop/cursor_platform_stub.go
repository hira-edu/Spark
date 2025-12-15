//go:build !windows && !linux && !darwin

package desktop

import (
	"fmt"
	"runtime"
)

func captureCursorPlatform() (*CursorData, []byte, error) {
	return nil, nil, fmt.Errorf("cursor capture unsupported on %s", runtime.GOOS)
}
