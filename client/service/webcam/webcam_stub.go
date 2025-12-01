//go:build (!linux || stub) && stub
// +build !linux stub
// +build stub

package webcam

import (
	"errors"

	"Spark/modules"
)

var errUnsupported = errors.New("webcam streaming is not implemented in this build")

func ListDevices() ([]string, error) {
	return nil, errUnsupported
}

func InitWebcam(pack modules.Packet) error {
	return errUnsupported
}

func PingWebcam(pack modules.Packet) {
	_ = pack
}

func KillWebcam(pack modules.Packet) {
	_ = pack
}

func HandleSelect(pack modules.Packet) error {
	return errUnsupported
}

func GetFrameData() <-chan []byte {
	return nil
}

func GetSessionUUID() string {
	return ""
}

func IsRunning() bool {
	return false
}

func Cleanup() {
}
