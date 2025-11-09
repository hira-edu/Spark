//go:build !windows || !cgo

package hookbridge

func nativeInit(cfg Config) error {
	return errNotSupported
}

func nativeApply(p Policy) error {
	return errNotSupported
}

func nativeRelease(connectionID string) error {
	return errNotSupported
}

func nativeShutdown() {}
