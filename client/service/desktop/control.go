package desktop

import (
	"Rocket/client/ipc"
	"Rocket/modules"
)

func HandleConfig(pack modules.Packet) error {
	if forwarded, err := relayDesktopCommand(pack, ipc.MsgTypeDesktopConfig); forwarded {
		return err
	}
	return nil
}

func HandleCodec(pack modules.Packet) error {
	return nil
}

func HandleClipboard(pack modules.Packet) error {
	return nil
}

func HandleAudio(pack modules.Packet) error {
	return nil
}
