//go:build !windows

package input

func WriteClipboardText(_ string) error {
	return errUnsupported
}

func ReadClipboardText() (string, error) {
	return "", errUnsupported
}

func ClipboardSupported() bool {
	return false
}
