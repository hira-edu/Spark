package utility

import (
	clientcfg "Spark/client/config"
	"Spark/modules"
	"Spark/server/common"
	servercfg "Spark/server/config"
	"Spark/utils"
	"Spark/utils/melody"
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Sender func(pack modules.Packet, session *melody.Session) bool

func shortCommit(commit string) string {
	if len(commit) == 0 {
		return `unknown`
	}
	if len(commit) <= 8 {
		return commit
	}
	return commit[:8] + `...`
}

// CheckForm checks if the form contains the required fields.
// Every request must contain connection UUID or device ID.
func CheckForm(ctx *gin.Context, form any) (string, bool) {
	var base struct {
		Conn   string `json:"uuid" yaml:"uuid" form:"uuid"`
		Device string `json:"device" yaml:"device" form:"device"`
	}
	if form != nil && ctx.ShouldBind(form) != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return ``, false
	}
	if ctx.ShouldBind(&base) != nil || (len(base.Conn) == 0 && len(base.Device) == 0) {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return ``, false
	}
	connUUID, ok := common.CheckDevice(base.Device, base.Conn)
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusBadGateway, modules.Packet{Code: 1, Msg: `${i18n|COMMON.DEVICE_NOT_EXIST}`})
		return ``, false
	}
	ctx.Request = ctx.Request.WithContext(context.WithValue(ctx.Request.Context(), `ConnUUID`, connUUID))
	common.Info(ctx, `API_BIND`, `success`, ``, map[string]any{
		`device`:   base.Device,
		`conn`:     base.Conn,
		`connUUID`: connUUID[:8] + `...`,
		`path`:     ctx.Request.URL.Path,
		`method`:   ctx.Request.Method,
	})
	return connUUID, true
}

// OnDevicePack handles events about device info.
// Such as websocket handshake and update device info.
// OnDevicePackWithUUID handles DEVICE_UP and DEVICE_UPDATE packets for any transport
// uuid: the session UUID
// remoteAddr: the WAN address (can be empty string)
// sendResponse: callback to send response packet (can be nil)
// closeConnection: callback to close connection (can be nil)
func OnDevicePackWithUUID(data []byte, uuid, remoteAddr string, sendResponse func(modules.Packet), closeConnection func()) error {
	var pack struct {
		Code   int            `json:"code,omitempty"`
		Act    string         `json:"act,omitempty"`
		Msg    string         `json:"msg,omitempty"`
		Device modules.Device `json:"data"`
	}
	err := utils.JSON.Unmarshal(data, &pack)
	if err != nil {
		if closeConnection != nil {
			closeConnection()
		}
		return err
	}

	// Set WAN address
	if remoteAddr != "" {
		pack.Device.WAN = remoteAddr
	} else {
		pack.Device.WAN = `Unknown`
	}

	if pack.Act == `DEVICE_UP` {
		// Check if this device has already connected.
		// If so, then find the session and let client quit.
		// This will keep only one connection remained per device.
		exSession := ``
		var kickedOldSession bool
		common.Devices.IterCb(func(existingUUID string, device *modules.Device) bool {
			if device.ID == pack.Device.ID {
				exSession = existingUUID
				// Try to kick old WebSocket session
				target, ok := common.Melody.GetSessionByUUID(existingUUID)
				if ok {
					kickedOldSession = true
					common.Warn(nil, `CLIENT_DUPLICATE`, ``, `kicking old session for same device`, map[string]any{
						`deviceID`:       pack.Device.ID[:16] + `...`,
						`oldSessionUUID`: existingUUID[:8] + `...`,
						`newSessionUUID`: uuid[:8] + `...`,
						`device`: map[string]any{
							`name`: device.Hostname,
							`ip`:   device.WAN,
						},
					})
					common.SendPack(modules.Packet{Act: `OFFLINE`}, target)
					target.Close()
				}
				// For non-WebSocket transports, we just log and replace
				// The old transport session will expire naturally
				return false
			}
			return true
		})
		if len(exSession) > 0 {
			common.Devices.Remove(exSession)
		}
		common.Devices.Set(uuid, &pack.Device)
		common.Info(nil, `CLIENT_ONLINE`, ``, ``, map[string]any{
			`device`: map[string]any{
				`name`:        pack.Device.Hostname,
				`ip`:          pack.Device.WAN,
				`sessionUUID`: uuid[:8] + `...`,
				`replacedOld`: kickedOldSession,
			},
		})
	} else {
		// DEVICE_UPDATE
		device, ok := common.Devices.Get(uuid)
		if ok {
			device.CPU = pack.Device.CPU
			device.RAM = pack.Device.RAM
			device.Net = pack.Device.Net
			device.Disk = pack.Device.Disk
			device.Uptime = pack.Device.Uptime
		}
	}

	// Send success response
	if sendResponse != nil {
		sendResponse(modules.Packet{Code: 0})
	}
	return nil
}

// OnDevicePack handles DEVICE_UP and DEVICE_UPDATE packets for WebSocket transport
// This is a wrapper around OnDevicePackWithUUID for backward compatibility
func OnDevicePack(data []byte, session *melody.Session) error {
	addr, ok := session.Get(`Address`)
	remoteAddr := ""
	if ok {
		remoteAddr = addr.(string)
	}

	return OnDevicePackWithUUID(
		data,
		session.UUID,
		remoteAddr,
		func(pack modules.Packet) {
			common.SendPack(pack, session)
		},
		func() {
			session.Close()
		},
	)
}

// CheckUpdate will check if client need update and return latest client if so.
func CheckUpdate(ctx *gin.Context) {
	clientIP := common.GetRemoteAddr(ctx)
	var form struct {
		OS     string `form:"os" binding:"required"`
		Arch   string `form:"arch" binding:"required"`
		Commit string `form:"commit" binding:"required"`
	}
	if err := ctx.ShouldBind(&form); err != nil {
		common.Warn(ctx, `CLIENT_UPDATE`, `fail`, `invalid parameters: `+err.Error(), map[string]any{
			`from`: clientIP,
		})
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}

	clientCommitStr := shortCommit(form.Commit)
	serverCommitStr := shortCommit(servercfg.Commit)

	common.Info(ctx, `CLIENT_UPDATE`, `check`, ``, map[string]any{
		`from`: clientIP,
		`client`: map[string]any{
			`os`:     form.OS,
			`arch`:   form.Arch,
			`commit`: clientCommitStr,
		},
		`server`:      serverCommitStr,
		`needsUpdate`: form.Commit != servercfg.Commit,
	})

	if form.Commit == servercfg.Commit {
		ctx.JSON(http.StatusOK, modules.Packet{Code: 0})
		common.Info(ctx, `CLIENT_UPDATE`, `success`, `already latest`, map[string]any{
			`from`: clientIP,
			`client`: map[string]any{
				`os`:     form.OS,
				`arch`:   form.Arch,
				`commit`: clientCommitStr,
			},
		})
		return
	}

	builtPath := fmt.Sprintf(servercfg.BuiltPath, form.OS, form.Arch)
	tpl, err := os.Open(builtPath)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, modules.Packet{Code: 1, Msg: `${i18n|GENERATOR.NO_PREBUILT_FOUND}`})
		common.Warn(ctx, `CLIENT_UPDATE`, `fail`, `prebuilt not found: `+builtPath, map[string]any{
			`from`: clientIP,
			`client`: map[string]any{
				`os`:     form.OS,
				`arch`:   form.Arch,
				`commit`: clientCommitStr,
			},
			`server`: serverCommitStr,
			`path`:   builtPath,
		})
		return
	}
	defer tpl.Close()

	// Validate that the client config size doesn't exceed the buffer size
	if ctx.Request.ContentLength > clientcfg.ConfigBufferSize {
		ctx.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, modules.Packet{Code: 1})
		common.Warn(ctx, `CLIENT_UPDATE`, `fail`, `config too large`, map[string]any{
			`client`: map[string]any{
				`os`:     form.OS,
				`arch`:   form.Arch,
				`commit`: form.Commit,
			},
			`server`: servercfg.Commit,
		})
		return
	}
	body, err := ctx.GetRawData()
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: 1})
		common.Warn(ctx, `CLIENT_UPDATE`, `fail`, `read config fail`, map[string]any{
			`client`: map[string]any{
				`os`:     form.OS,
				`arch`:   form.Arch,
				`commit`: form.Commit,
			},
			`server`: servercfg.Commit,
		})
		return
	}
	session := common.CheckClientReq(ctx)
	if session == nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, modules.Packet{Code: 1})
		common.Warn(ctx, `CLIENT_UPDATE`, `fail`, `check config fail`, map[string]any{
			`client`: map[string]any{
				`os`:     form.OS,
				`arch`:   form.Arch,
				`commit`: form.Commit,
			},
			`server`: servercfg.Commit,
		})
		return
	}

	common.Info(ctx, `CLIENT_UPDATE`, `success`, `updating`, map[string]any{
		`client`: map[string]any{
			`os`:     form.OS,
			`arch`:   form.Arch,
			`commit`: form.Commit,
		},
		`server`: servercfg.Commit,
	})

	ctx.Header(`Spark-Commit`, servercfg.Commit)
	ctx.Header(`Accept-Ranges`, `none`)
	ctx.Header(`Content-Transfer-Encoding`, `binary`)
	ctx.Header(`Content-Type`, `application/octet-stream`)
	trailer := clientcfg.BuildTrailerFooter(body)
	if stat, err := tpl.Stat(); err == nil {
		total := stat.Size() + int64(len(body)) + int64(clientcfg.TrailerFooterSize)
		ctx.Header(`Content-Length`, strconv.FormatInt(total, 10))
	}
	io.Copy(ctx.Writer, tpl)
	ctx.Writer.Write(body)
	ctx.Writer.Write(trailer)
}

// ExecDeviceCmd execute command on device.
func ExecDeviceCmd(ctx *gin.Context) {
	var form struct {
		Cmd  string `json:"cmd" yaml:"cmd" form:"cmd" binding:"required"`
		Args string `json:"args" yaml:"args" form:"args"`
	}
	target, ok := CheckForm(ctx, &form)
	if !ok {
		return
	}
	if len(form.Cmd) == 0 {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	trigger := utils.GetStrUUID()
	common.SendPackByUUID(modules.Packet{Act: `COMMAND_EXEC`, Data: gin.H{`cmd`: form.Cmd, `args`: form.Args}, Event: trigger}, target)
	ok = common.AddEventOnce(func(p modules.Packet, _ *melody.Session) {
		if p.Code != 0 {
			common.Warn(ctx, `EXEC_COMMAND`, `fail`, p.Msg, map[string]any{
				`cmd`:  form.Cmd,
				`args`: form.Args,
			})
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, modules.Packet{Code: 1, Msg: p.Msg})
		} else {
			common.Info(ctx, `EXEC_COMMAND`, `success`, ``, map[string]any{
				`cmd`:  form.Cmd,
				`args`: form.Args,
			})
			ctx.JSON(http.StatusOK, modules.Packet{Code: 0})
		}
	}, target, trigger, 5*time.Second)
	if !ok {
		common.Warn(ctx, `EXEC_COMMAND`, `fail`, `timeout`, map[string]any{
			`cmd`:  form.Cmd,
			`args`: form.Args,
		})
		ctx.AbortWithStatusJSON(http.StatusGatewayTimeout, modules.Packet{Code: 1, Msg: `${i18n|COMMON.RESPONSE_TIMEOUT}`})
	}
}

// GetDevices will return all info about all clients.
func GetDevices(ctx *gin.Context) {
	devices := map[string]any{}
	common.Devices.IterCb(func(uuid string, device *modules.Device) bool {
		devices[uuid] = *device
		return true
	})
	ctx.JSON(http.StatusOK, modules.Packet{Code: 0, Data: devices})
}

// CallDevice will call client with command from browser.
func CallDevice(ctx *gin.Context) {
	act := strings.ToUpper(ctx.Param(`act`))
	if len(act) == 0 {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	{
		actions := []string{`LOCK`, `LOGOFF`, `HIBERNATE`, `SUSPEND`, `RESTART`, `SHUTDOWN`, `OFFLINE`}
		ok := false
		for _, v := range actions {
			if v == act {
				ok = true
				break
			}
		}
		if !ok {
			common.Warn(ctx, `CALL_DEVICE`, `fail`, `invalid act`, map[string]any{
				`act`: act,
			})
			ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
			return
		}
	}
	connUUID, ok := CheckForm(ctx, nil)
	if !ok {
		return
	}
	trigger := utils.GetStrUUID()
	common.SendPackByUUID(modules.Packet{Act: act, Event: trigger}, connUUID)
	ok = common.AddEventOnce(func(p modules.Packet, _ *melody.Session) {
		if p.Code != 0 {
			common.Warn(ctx, `CALL_DEVICE`, `fail`, p.Msg, map[string]any{
				`act`: act,
			})
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, modules.Packet{Code: 1, Msg: p.Msg})
		} else {
			common.Info(ctx, `CALL_DEVICE`, `success`, ``, map[string]any{
				`act`: act,
			})
			ctx.JSON(http.StatusOK, modules.Packet{Code: 0})
		}
	}, connUUID, trigger, 5*time.Second)
	if !ok {
		//This means the client is offline.
		//So we take this as a success.
		common.Info(ctx, `CALL_DEVICE`, `success`, ``, map[string]any{
			`act`: act,
		})
		ctx.JSON(http.StatusOK, modules.Packet{Code: 0})
	}
}

func SimpleEncrypt(data []byte, session *melody.Session) []byte {
	temp, ok := session.Get(`Secret`)
	if !ok {
		return nil
	}
	secret := temp.([]byte)
	return utils.StreamEncrypt(data, secret)
}

func SimpleDecrypt(data []byte, session *melody.Session) []byte {
	temp, ok := session.Get(`Secret`)
	if !ok {
		return nil
	}
	secret := temp.([]byte)
	return utils.StreamDecrypt(data, secret)
}

func WSHealthCheck(container *melody.Melody, sender Sender) {
	const MaxIdleSeconds = 300
	ping := func(uuid string, s *melody.Session) {
		if !sender(modules.Packet{Act: `PING`}, s) {
			s.Close()
		}
	}
	for now := range time.NewTicker(60 * time.Second).C {
		timestamp := now.Unix()
		// stores sessions to be disconnected
		queue := make([]*melody.Session, 0)
		container.IterSessions(func(uuid string, s *melody.Session) bool {
			go ping(uuid, s)
			val, ok := s.Get(`LastPack`)
			if !ok {
				queue = append(queue, s)
				return true
			}
			lastPack, ok := val.(int64)
			if !ok {
				queue = append(queue, s)
				return true
			}
			if timestamp-lastPack > MaxIdleSeconds {
				queue = append(queue, s)
			}
			return true
		})
		for i := 0; i < len(queue); i++ {
			queue[i].Close()
		}
	}
}
