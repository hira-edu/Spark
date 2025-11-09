//go:build !windows

package desktop

import (
	"errors"

	"Spark/modules"
)

var errUnsupported = errors.New("desktop: feature available on Windows endpoints only")

func InitDesktop(pack modules.Packet) error {
	return errUnsupported
}

func PingDesktop(pack modules.Packet) {}

func KillDesktop(pack modules.Packet) {}

func GetDesktop(pack modules.Packet) {}

func ListMonitors(pack modules.Packet) {}

func SetMonitor(pack modules.Packet) {}

func SetQuality(pack modules.Packet) {}

func HandleDesktopInput(pack modules.Packet) {}

func ClipboardPush(pack modules.Packet) {}

func ClipboardPull(pack modules.Packet) {}
