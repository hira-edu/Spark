package file

import (
	"Rocket/modules"
	"Rocket/server/cluster"
	"Rocket/server/common"
	"Rocket/server/handler/bridge"
	"Rocket/server/handler/utility"
	"Rocket/utils"
	"Rocket/utils/melody"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// RemoveDeviceFiles will try to get send a packet to
// client and let it upload the file specified.
func RemoveDeviceFiles(ctx *gin.Context) {
	var form struct {
		Files []string `json:"files" yaml:"files" form:"files" binding:"required"`
	}
	target, ok := utility.CheckForm(ctx, &form)
	if !ok {
		return
	}
	if len(form.Files) == 0 {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	trigger := utils.GetStrUUID()
	common.SendPackByUUID(modules.Packet{Act: `FILES_REMOVE`, Data: gin.H{`files`: form.Files}, Event: trigger}, target)
	ok = common.AddEventOnce(func(p modules.Packet, _ *melody.Session) {
		if p.Code != 0 {
			common.Warn(ctx, `REMOVE_FILES`, `fail`, p.Msg, map[string]any{
				`files`: form.Files,
			})
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, modules.Packet{Code: 1, Msg: p.Msg})
		} else {
			common.Info(ctx, `REMOVE_FILES`, `success`, ``, map[string]any{
				`files`: form.Files,
			})
			ctx.JSON(http.StatusOK, modules.Packet{Code: 0})
		}
	}, target, trigger, 5*time.Second)
	if !ok {
		common.Warn(ctx, `REMOVE_FILES`, `fail`, `timeout`, map[string]any{
			`files`: form.Files,
		})
		ctx.AbortWithStatusJSON(http.StatusGatewayTimeout, modules.Packet{Code: 1, Msg: `${i18n|COMMON.RESPONSE_TIMEOUT}`})
	}
}

// MkdirDeviceDir creates a directory on the target device.
func MkdirDeviceDir(ctx *gin.Context) {
	var form struct {
		Path string `json:"path" yaml:"path" form:"path" binding:"required"`
	}
	target, ok := utility.CheckForm(ctx, &form)
	if !ok {
		return
	}
	if strings.TrimSpace(form.Path) == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}

	trigger := utils.GetStrUUID()
	common.SendPackByUUID(modules.Packet{Act: `FILES_MKDIR`, Data: gin.H{`path`: form.Path}, Event: trigger}, target)
	ok = common.AddEventOnce(func(p modules.Packet, _ *melody.Session) {
		if p.Code != 0 {
			common.Warn(ctx, `MKDIR`, `fail`, p.Msg, map[string]any{
				`path`: form.Path,
			})
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, modules.Packet{Code: 1, Msg: p.Msg})
		} else {
			common.Info(ctx, `MKDIR`, `success`, ``, map[string]any{
				`path`: form.Path,
			})
			ctx.JSON(http.StatusOK, modules.Packet{Code: 0})
		}
	}, target, trigger, 5*time.Second)
	if !ok {
		common.Warn(ctx, `MKDIR`, `fail`, `timeout`, map[string]any{
			`path`: form.Path,
		})
		ctx.AbortWithStatusJSON(http.StatusGatewayTimeout, modules.Packet{Code: 1, Msg: `${i18n|COMMON.RESPONSE_TIMEOUT}`})
	}
}

// MoveDevicePath moves/renames a path on the target device.
func MoveDevicePath(ctx *gin.Context) {
	var form struct {
		Src string `json:"src" yaml:"src" form:"src" binding:"required"`
		Dst string `json:"dst" yaml:"dst" form:"dst" binding:"required"`
	}
	target, ok := utility.CheckForm(ctx, &form)
	if !ok {
		return
	}
	if strings.TrimSpace(form.Src) == "" || strings.TrimSpace(form.Dst) == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}

	trigger := utils.GetStrUUID()
	common.SendPackByUUID(modules.Packet{Act: `FILES_MOVE`, Data: gin.H{`src`: form.Src, `dst`: form.Dst}, Event: trigger}, target)
	ok = common.AddEventOnce(func(p modules.Packet, _ *melody.Session) {
		if p.Code != 0 {
			common.Warn(ctx, `MOVE`, `fail`, p.Msg, map[string]any{
				`src`: form.Src,
				`dst`: form.Dst,
			})
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, modules.Packet{Code: 1, Msg: p.Msg})
		} else {
			common.Info(ctx, `MOVE`, `success`, ``, map[string]any{
				`src`: form.Src,
				`dst`: form.Dst,
			})
			ctx.JSON(http.StatusOK, modules.Packet{Code: 0})
		}
	}, target, trigger, 5*time.Second)
	if !ok {
		common.Warn(ctx, `MOVE`, `fail`, `timeout`, map[string]any{
			`src`: form.Src,
			`dst`: form.Dst,
		})
		ctx.AbortWithStatusJSON(http.StatusGatewayTimeout, modules.Packet{Code: 1, Msg: `${i18n|COMMON.RESPONSE_TIMEOUT}`})
	}
}

// CopyDevicePath copies a path on the target device.
func CopyDevicePath(ctx *gin.Context) {
	var form struct {
		Src string `json:"src" yaml:"src" form:"src" binding:"required"`
		Dst string `json:"dst" yaml:"dst" form:"dst" binding:"required"`
	}
	target, ok := utility.CheckForm(ctx, &form)
	if !ok {
		return
	}
	if strings.TrimSpace(form.Src) == "" || strings.TrimSpace(form.Dst) == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}

	trigger := utils.GetStrUUID()
	common.SendPackByUUID(modules.Packet{Act: `FILES_COPY`, Data: gin.H{`src`: form.Src, `dst`: form.Dst}, Event: trigger}, target)
	ok = common.AddEventOnce(func(p modules.Packet, _ *melody.Session) {
		if p.Code != 0 {
			common.Warn(ctx, `COPY`, `fail`, p.Msg, map[string]any{
				`src`: form.Src,
				`dst`: form.Dst,
			})
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, modules.Packet{Code: 1, Msg: p.Msg})
		} else {
			common.Info(ctx, `COPY`, `success`, ``, map[string]any{
				`src`: form.Src,
				`dst`: form.Dst,
			})
			ctx.JSON(http.StatusOK, modules.Packet{Code: 0})
		}
	}, target, trigger, 5*time.Second)
	if !ok {
		common.Warn(ctx, `COPY`, `fail`, `timeout`, map[string]any{
			`src`: form.Src,
			`dst`: form.Dst,
		})
		ctx.AbortWithStatusJSON(http.StatusGatewayTimeout, modules.Packet{Code: 1, Msg: `${i18n|COMMON.RESPONSE_TIMEOUT}`})
	}
}

// ListDeviceFiles will list files on remote client
func ListDeviceFiles(ctx *gin.Context) {
	var form struct {
		Path string `json:"path" yaml:"path" form:"path" binding:"required"`
	}
	target, ok := utility.CheckForm(ctx, &form)
	if !ok {
		return
	}
	trigger := utils.GetStrUUID()
	common.SendPackByUUID(modules.Packet{Act: `FILES_LIST`, Data: gin.H{`path`: form.Path}, Event: trigger}, target)
	ok = common.AddEventOnce(func(p modules.Packet, _ *melody.Session) {
		if p.Code != 0 {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, modules.Packet{Code: 1, Msg: p.Msg})
		} else {
			ctx.JSON(http.StatusOK, modules.Packet{Code: 0, Data: p.Data})
		}
	}, target, trigger, 5*time.Second)
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusGatewayTimeout, modules.Packet{Code: 1, Msg: `${i18n|COMMON.RESPONSE_TIMEOUT}`})
	}
}

// GetDeviceFiles will try to get send a packet to
// client and let it upload the file specified.
func GetDeviceFiles(ctx *gin.Context) {
	var form struct {
		Files   []string `json:"files" yaml:"files" form:"files" binding:"required"`
		Preview bool     `json:"preview" yaml:"preview" form:"preview"`
	}
	target, ok := utility.CheckForm(ctx, &form)
	if !ok {
		return
	}
	if len(form.Files) == 0 {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	bridgeID := utils.GetStrUUID()
	trigger := utils.GetStrUUID()
	var rangeStart, rangeEnd int64
	var err error
	partial := false
	{
		command := gin.H{`files`: form.Files, `bridge`: bridgeID}
		rangeHeader := ctx.GetHeader(`Range`)
		if len(rangeHeader) > 6 {
			if rangeHeader[:6] != `bytes=` {
				ctx.AbortWithStatus(http.StatusRequestedRangeNotSatisfiable)
				return
			}
			rangeHeader = strings.TrimSpace(rangeHeader[6:])
			rangesList := strings.Split(rangeHeader, `,`)
			if len(rangesList) > 1 {
				ctx.AbortWithStatus(http.StatusRequestedRangeNotSatisfiable)
				return
			}
			r := strings.Split(rangesList[0], `-`)
			rangeStart, err = strconv.ParseInt(r[0], 10, 64)
			if err != nil {
				ctx.AbortWithStatus(http.StatusRequestedRangeNotSatisfiable)
				return
			}
			if len(r[1]) > 0 {
				rangeEnd, err = strconv.ParseInt(r[1], 10, 64)
				if err != nil {
					ctx.AbortWithStatus(http.StatusRequestedRangeNotSatisfiable)
					return
				}
				if rangeEnd < rangeStart {
					ctx.AbortWithStatus(http.StatusRequestedRangeNotSatisfiable)
					return
				}
				command[`end`] = rangeEnd
			}
			command[`start`] = rangeStart
			partial = true
		}
		common.SendPackByUUID(modules.Packet{Act: `FILES_UPLOAD`, Data: command, Event: trigger}, target)
	}
	wait := make(chan bool)
	called := false
	common.AddEvent(func(p modules.Packet, _ *melody.Session) {
		called = true
		bridge.RemoveBridge(bridgeID)
		common.RemoveEvent(trigger)
		common.Warn(ctx, `READ_FILES`, `fail`, p.Msg, map[string]any{
			`files`: form.Files,
		})
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, modules.Packet{Code: 1, Msg: p.Msg})
		wait <- false
	}, target, trigger)
	instance := bridge.AddBridgeWithDst(nil, bridgeID, ctx)
	instance.OnPush = func(bridge *bridge.Bridge) {
		called = true
		common.RemoveEvent(trigger)
		src := bridge.Src
		for k, v := range src.Request.Header {
			if strings.HasPrefix(k, `File`) {
				ctx.Header(k, v[0])
			}
		}
		if !form.Preview {
			if len(form.Files) == 1 {
				ctx.Header(`Accept-Ranges`, `bytes`)
				if src.Request.ContentLength > 0 {
					ctx.Header(`Content-Length`, strconv.FormatInt(src.Request.ContentLength, 10))
				}
			} else {
				ctx.Header(`Accept-Ranges`, `none`)
			}
			ctx.Header(`Content-Transfer-Encoding`, `binary`)
			ctx.Header(`Content-Type`, `application/octet-stream`)
			filename := src.GetHeader(`FileName`)
			if len(filename) == 0 {
				if len(form.Files) > 1 {
					filename = `Archive.zip`
				} else {
					filename = path.Base(strings.ReplaceAll(form.Files[0], `\`, `/`))
				}
			}
			ctx.Header(`Content-Disposition`, fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, filename, url.PathEscape(filename)))
		}

		if partial {
			if rangeEnd == 0 {
				rangeEnd, err = strconv.ParseInt(src.GetHeader(`FileSize`), 10, 64)
				if err == nil {
					ctx.Header(`Content-Range`, fmt.Sprintf(`bytes %d-%d/%d`, rangeStart, rangeEnd-1, rangeEnd))
				}
			} else {
				ctx.Header(`Content-Range`, fmt.Sprintf(`bytes %d-%d/%v`, rangeStart, rangeEnd, src.GetHeader(`FileSize`)))
			}
			ctx.Status(http.StatusPartialContent)
		} else {
			ctx.Status(http.StatusOK)
		}
	}
	instance.OnFinish = func(bridge *bridge.Bridge) {
		if called {
			common.Info(ctx, `READ_FILES`, `success`, ``, map[string]any{
				`files`: form.Files,
			})
		}
		wait <- false
	}
	select {
	case <-wait:
	case <-time.After(5 * time.Second):
		if !called {
			bridge.RemoveBridge(bridgeID)
			common.RemoveEvent(trigger)
			common.Warn(ctx, `READ_FILES`, `fail`, `timeout`, map[string]any{
				`files`: form.Files,
			})
			ctx.AbortWithStatusJSON(http.StatusGatewayTimeout, modules.Packet{Code: 1, Msg: `${i18n|COMMON.RESPONSE_TIMEOUT}`})
		} else {
			<-wait
		}
	}
	close(wait)
}

// GetDeviceTextFile will try to get send a packet to
// client and let it upload the text file.
func GetDeviceTextFile(ctx *gin.Context) {
	var form struct {
		File string `json:"file" yaml:"file" form:"file" binding:"required"`
	}
	target, ok := utility.CheckForm(ctx, &form)
	if !ok {
		return
	}
	if len(form.File) == 0 {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	bridgeID := utils.GetStrUUID()
	trigger := utils.GetStrUUID()
	common.SendPackByUUID(modules.Packet{Act: `FILE_UPLOAD_TEXT`, Data: gin.H{
		`file`:   form.File,
		`bridge`: bridgeID,
	}, Event: trigger}, target)
	wait := make(chan bool)
	called := false
	common.AddEvent(func(p modules.Packet, _ *melody.Session) {
		called = true
		bridge.RemoveBridge(bridgeID)
		common.RemoveEvent(trigger)
		common.Warn(ctx, `READ_TEXT_FILE`, `fail`, p.Msg, map[string]any{
			`file`: form.File,
		})
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, modules.Packet{Code: 1, Msg: p.Msg})
		wait <- false
	}, target, trigger)
	instance := bridge.AddBridgeWithDst(nil, bridgeID, ctx)
	instance.OnPush = func(bridge *bridge.Bridge) {
		called = true
		common.RemoveEvent(trigger)
		src := bridge.Src
		for k, v := range src.Request.Header {
			if strings.HasPrefix(k, `File`) {
				ctx.Header(k, v[0])
			}
		}
		ctx.Header(`Accept-Ranges`, `none`)
		ctx.Header(`Content-Transfer-Encoding`, `binary`)
		ctx.Header(`Content-Type`, `application/octet-stream`)
		filename := src.GetHeader(`FileName`)
		if len(filename) == 0 {
			filename = path.Base(strings.ReplaceAll(form.File, `\`, `/`))
		}
		ctx.Header(`Content-Disposition`, fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, filename, url.PathEscape(filename)))
		ctx.Status(http.StatusOK)
	}
	instance.OnFinish = func(bridge *bridge.Bridge) {
		if called {
			common.Info(ctx, `READ_TEXT_FILE`, `success`, ``, map[string]any{
				`file`: form.File,
			})
		}
		wait <- false
	}
	select {
	case <-wait:
	case <-time.After(5 * time.Second):
		if !called {
			bridge.RemoveBridge(bridgeID)
			common.RemoveEvent(trigger)
			common.Warn(ctx, `READ_TEXT_FILE`, `fail`, `timeout`, map[string]any{
				`file`: form.File,
			})
			ctx.AbortWithStatusJSON(http.StatusGatewayTimeout, modules.Packet{Code: 1, Msg: `${i18n|COMMON.RESPONSE_TIMEOUT}`})
		} else {
			<-wait
		}
	}
	close(wait)
}

// UploadToDevice handles file from browser
// and transfer it to device.
func UploadToDevice(ctx *gin.Context) {
	deviceID := strings.TrimSpace(ctx.Query(`device`))
	if deviceID == "" {
		deviceID = strings.TrimSpace(ctx.PostForm(`device`))
	}
	if deviceID == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	if cluster.RedirectIfNeeded(ctx, deviceID) {
		return
	}
	target, ok := common.CheckDevice(deviceID, ``)
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusBadGateway, modules.Packet{Code: 1, Msg: `${i18n|COMMON.DEVICE_NOT_EXIST}`})
		return
	}

	destPath := strings.TrimSpace(ctx.Query(`path`))
	if destPath == "" {
		destPath = strings.TrimSpace(ctx.PostForm(`path`))
	}
	fileName := strings.TrimSpace(ctx.Query(`file`))
	if fileName == "" {
		fileName = strings.TrimSpace(ctx.PostForm(`file`))
	}
	if destPath == "" || fileName == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}

	bridgeID := utils.GetStrUUID()
	trigger := utils.GetStrUUID()
	wait := make(chan bool)
	called := false
	response := false
	fileDest := path.Join(destPath, fileName)
	fileSize := ctx.Request.ContentLength
	common.AddEvent(func(p modules.Packet, _ *melody.Session) {
		called = true
		response = true
		bridge.RemoveBridge(bridgeID)
		common.RemoveEvent(trigger)
		common.Warn(ctx, `UPLOAD_FILE`, `fail`, p.Msg, map[string]any{
			`dest`: fileDest,
			`size`: fileSize,
		})
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, modules.Packet{Code: 1, Msg: p.Msg})
		wait <- false
	}, target, trigger)
	instance := bridge.AddBridgeWithSrc(nil, bridgeID, ctx)
	instance.OnPull = func(bridge *bridge.Bridge) {
		called = true
		common.RemoveEvent(trigger)
		dst := bridge.Dst
		if ctx.Request.ContentLength > 0 {
			dst.Header(`Content-Length`, strconv.FormatInt(ctx.Request.ContentLength, 10))
		}
		dst.Header(`Accept-Ranges`, `none`)
		dst.Header(`Content-Transfer-Encoding`, `binary`)
		dst.Header(`Content-Type`, `application/octet-stream`)
		dst.Header(`Content-Disposition`, fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, fileName, url.PathEscape(fileName)))
	}
	instance.OnFinish = func(bridge *bridge.Bridge) {
		if called {
			common.Info(ctx, `UPLOAD_FILE`, `success`, ``, map[string]any{
				`dest`: fileDest,
				`size`: fileSize,
			})
		}
		wait <- false
	}
	common.SendPackByUUID(modules.Packet{Act: `FILES_FETCH`, Data: gin.H{
		`path`:   destPath,
		`file`:   fileName,
		`bridge`: bridgeID,
	}, Event: trigger}, target)
	select {
	case <-wait:
		if !response {
			ctx.JSON(http.StatusOK, modules.Packet{Code: 0})
		}
	case <-time.After(5 * time.Second):
		if !called {
			bridge.RemoveBridge(bridgeID)
			common.RemoveEvent(trigger)
			if !response {
				common.Warn(ctx, `UPLOAD_FILE`, `fail`, `timeout`, map[string]any{
					`dest`: fileDest,
					`size`: fileSize,
				})
				ctx.AbortWithStatusJSON(http.StatusGatewayTimeout, modules.Packet{Code: 1, Msg: `${i18n|COMMON.RESPONSE_TIMEOUT}`})
			}
		} else {
			<-wait
			if !response {
				ctx.JSON(http.StatusOK, modules.Packet{Code: 0})
			}
		}
	}
	close(wait)
}

// ExecDeviceFile runs a remote file on the target device.
func ExecDeviceFile(ctx *gin.Context) {
	var form struct {
		Path    string `json:"path" yaml:"path" form:"path" binding:"required"`
		Args    string `json:"args" yaml:"args" form:"args"`
		Workdir string `json:"workdir" yaml:"workdir" form:"workdir"`
	}
	target, ok := utility.CheckForm(ctx, &form)
	if !ok {
		return
	}
	if len(strings.TrimSpace(form.Path)) == 0 {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}

	payload := gin.H{`path`: form.Path}
	if len(strings.TrimSpace(form.Args)) > 0 {
		payload[`args`] = form.Args
	}
	if len(strings.TrimSpace(form.Workdir)) > 0 {
		payload[`workdir`] = form.Workdir
	}

	trigger := utils.GetStrUUID()
	common.SendPackByUUID(modules.Packet{Act: `FILE_EXEC`, Data: payload, Event: trigger}, target)
	ok = common.AddEventOnce(func(p modules.Packet, _ *melody.Session) {
		if p.Code != 0 {
			common.Warn(ctx, `FILE_EXEC`, `fail`, p.Msg, map[string]any{
				`path`: form.Path,
				`args`: form.Args,
			})
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, modules.Packet{Code: 1, Msg: p.Msg})
		} else {
			common.Info(ctx, `FILE_EXEC`, `success`, ``, map[string]any{
				`path`: form.Path,
				`args`: form.Args,
				`pid`:  p.Data[`pid`],
			})
			ctx.JSON(http.StatusOK, modules.Packet{Code: 0, Data: p.Data})
		}
	}, target, trigger, 5*time.Second)
	if !ok {
		common.Warn(ctx, `FILE_EXEC`, `fail`, `timeout`, map[string]any{
			`path`: form.Path,
			`args`: form.Args,
		})
		ctx.AbortWithStatusJSON(http.StatusGatewayTimeout, modules.Packet{Code: 1, Msg: `${i18n|COMMON.RESPONSE_TIMEOUT}`})
	}
}
