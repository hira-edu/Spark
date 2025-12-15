//go:build linux

package desktop

import (
	"fmt"
	"sync"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xfixes"
)

var (
	x11CursorOnce sync.Once
	x11CursorConn *xgb.Conn
	x11CursorErr  error
	x11CursorMu   sync.Mutex
)

func initX11Cursor() (*xgb.Conn, error) {
	x11CursorOnce.Do(func() {
		conn, err := xgb.NewConn()
		if err != nil {
			x11CursorErr = err
			return
		}

		// Initialize XFixes for GetCursorImage.
		if err := xfixes.Init(conn); err != nil {
			_ = conn.Close()
			x11CursorErr = err
			return
		}

		// Best-effort version probe.
		_, _ = xfixes.QueryVersion(conn, 4, 0).Reply()

		x11CursorConn = conn
	})
	return x11CursorConn, x11CursorErr
}

func captureCursorPlatform() (*CursorData, []byte, error) {
	conn, err := initX11Cursor()
	if err != nil {
		return nil, nil, err
	}
	if conn == nil {
		return nil, nil, fmt.Errorf("x11: no connection")
	}

	// xgb.Conn is not documented as goroutine-safe for concurrent requests; serialize.
	x11CursorMu.Lock()
	defer x11CursorMu.Unlock()

	reply, err := xfixes.GetCursorImage(conn).Reply()
	if err != nil {
		return nil, nil, err
	}
	if reply == nil || reply.Width == 0 || reply.Height == 0 {
		return &CursorData{Visible: false}, nil, nil
	}

	width := int32(reply.Width)
	height := int32(reply.Height)

	rgba := make([]byte, int(width*height*4))
	for i, pixel := range reply.CursorImage {
		// XFixes cursor pixels are 0xAARRGGBB.
		a := byte(pixel >> 24)
		r := byte(pixel >> 16)
		g := byte(pixel >> 8)
		b := byte(pixel)
		o := i * 4
		rgba[o+0] = r
		rgba[o+1] = g
		rgba[o+2] = b
		rgba[o+3] = a
	}

	return &CursorData{
		X:       int32(reply.X),
		Y:       int32(reply.Y),
		HotX:    int32(reply.Xhot),
		HotY:    int32(reply.Yhot),
		Width:   width,
		Height:  height,
		Visible: true,
	}, rgba, nil
}
