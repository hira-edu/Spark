//go:build stub
// +build stub

package audio

import (
	"errors"

	"Spark/modules"
)

var errUnsupported = errors.New("audio streaming is not implemented in this build")

// ListDevices returns no devices for the stub.
func ListDevices() ([]string, error) {
	return nil, errUnsupported
}

func InitAudio(pack modules.Packet) error {
	return errUnsupported
}

func PingAudio(pack modules.Packet) {
	_ = pack
}

func KillAudio(pack modules.Packet) {
	_ = pack
}

func HandleSelect(pack modules.Packet) error {
	return errUnsupported
}

func GetAudioData() <-chan []byte {
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
