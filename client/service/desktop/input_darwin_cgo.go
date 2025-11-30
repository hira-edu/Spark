//go:build darwin && cgo
// +build darwin,cgo

package desktop

func movePointerAbsolute(_, _ int) error { return errInputUnsupported }
func movePointerRelative(_, _ int) error { return errInputUnsupported }
func mouseButton(_ string, _ bool) error  { return errInputUnsupported }
func scrollMouse(_, _ int) error          { return errInputUnsupported }
func keyEvent(_ string, _ bool) error     { return errInputUnsupported }
