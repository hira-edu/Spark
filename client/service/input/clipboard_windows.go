//go:build windows

package input

import "github.com/atotto/clipboard"

func ClipboardSupported() bool {
	return true
}

func WriteClipboardText(text string) error {
	return clipboard.WriteAll(text)
}

func ReadClipboardText() (string, error) {
	return clipboard.ReadAll()
}
