package core

import (
	"Rocket/client/common"
	"Rocket/client/config"
	"Rocket/client/service/audio"
	"Rocket/client/service/basic"
	"Rocket/client/service/desktop"
	"Rocket/client/service/file"
	"Rocket/client/service/process"
	Screenshot "Rocket/client/service/screenshot"
	"Rocket/client/service/terminal"
	"Rocket/client/service/webcam"
	"Rocket/client/telemetry"
	"Rocket/modules"
	"github.com/kataras/golog"
	"net/url"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
)

var handlers = map[string]func(pack modules.Packet, wsConn *common.Conn){
	`PING`:                  ping,
	`OFFLINE`:               offline,
	`LOCK`:                  lock,
	`LOGOFF`:                logoff,
	`HIBERNATE`:             hibernate,
	`SUSPEND`:               suspend,
	`RESTART`:               restart,
	`SHUTDOWN`:              shutdown,
	`SCREENSHOT`:            screenshot,
	`TERMINAL_INIT`:         initTerminal,
	`TERMINAL_INPUT`:        inputTerminal,
	`TERMINAL_RESIZE`:       resizeTerminal,
	`TERMINAL_PING`:         pingTerminal,
	`TERMINAL_KILL`:         killTerminal,
	`FILES_LIST`:            listFiles,
	`FILES_FETCH`:           fetchFile,
	`FILES_REMOVE`:          removeFiles,
	`FILES_UPLOAD`:          uploadFiles,
	`FILES_MKDIR`:           mkdirFiles,
	`FILES_MOVE`:            moveFiles,
	`FILES_COPY`:            copyFiles,
	`FILE_UPLOAD_TEXT`:      uploadTextFile,
	`FILE_EXEC`:             execFile,
	`PROCESSES_LIST`:        listProcesses,
	`PROCESS_KILL`:          killProcess,
	`DESKTOP_INIT`:          initDesktop,
	`DESKTOP_PING`:          pingDesktop,
	`DESKTOP_KILL`:          killDesktop,
	`DESKTOP_SHOT`:          getDesktop,
	`DESKTOP_INPUT`:         inputDesktop,
	`DESKTOP_CONFIG`:        configDesktop,
	`DESKTOP_CLIPBOARD`:     clipboardDesktop,
	`DESKTOP_FILE_DROP`:     fileDropDesktop,
	`DESKTOP_AUDIO`:         audioDesktop,
	`DESKTOP_CODEC`:         codecDesktop,
	`DESKTOP_WEBRTC_OFFER`:  webrtcOffer,
	`DESKTOP_WEBRTC_ANSWER`: webrtcAnswer,
	`DESKTOP_WEBRTC_ICE`:    webrtcICE,
	`COMMAND_EXEC`:          execCommand,
	`WEBCAM_LIST`:           listWebcams,
	`WEBCAM_INIT`:           initWebcam,
	`WEBCAM_PING`:           pingWebcam,
	`WEBCAM_KILL`:           killWebcam,
	`WEBCAM_SELECT`:         selectWebcam,
	`AUDIO_LIST`:            listAudioDevices,
	`AUDIO_INIT`:            initAudio,
	`AUDIO_PING`:            pingAudio,
	`AUDIO_KILL`:            killAudio,
	`AUDIO_SELECT`:          selectAudio,
	`REDIRECT`:              handleRedirect,
}

// RegisterHandler allows overriding handlers at runtime
func RegisterHandler(action string, handler func(pack modules.Packet, wsConn *common.Conn)) {
	handlers[action] = handler
}

// ping responds to server PING with PONG and device status update (RFC 6455 keepalive).
// This implements WebSocket liveness detection with automatic RTT measurement.
// Server uses PING/PONG to:
// - Detect dead connections (no PONG = close connection)
// - Measure round-trip time (RTT) for adaptive quality
// - Keep NAT/firewall holes open (prevent timeout)
//
// Best Practices (2025):
// - Respond to PING as quickly as possible (minimize RTT measurement error)
// - Send device metrics with PONG for server-side monitoring
// - Use atomic operations if tracking client-side RTT statistics
func ping(pack modules.Packet, wsConn *common.Conn) {
	// Send PONG response immediately (callback uses same event ID for RTT tracking)
	wsConn.SendCallback(modules.Packet{Code: 0}, pack)

	// Include updated device metrics (CPU, RAM, network usage)
	// This piggybacks on PONG to reduce overhead
	device, err := GetPartialInfo()
	if err != nil {
		golog.Error(err)
		return
	}
	wsConn.SendPack(modules.CommonPack{Act: `DEVICE_UPDATE`, Data: *device})
}

func offline(pack modules.Packet, wsConn *common.Conn) {
	wsConn.SendCallback(modules.Packet{Code: 0}, pack)
	stopAndExit(wsConn, 0)
}

func lock(pack modules.Packet, wsConn *common.Conn) {
	err := basic.Lock()
	if err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
	} else {
		wsConn.SendCallback(modules.Packet{Code: 0}, pack)
	}
}

func logoff(pack modules.Packet, wsConn *common.Conn) {
	err := basic.Logoff()
	if err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
	} else {
		wsConn.SendCallback(modules.Packet{Code: 0}, pack)
	}
}

func hibernate(pack modules.Packet, wsConn *common.Conn) {
	err := basic.Hibernate()
	if err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
	} else {
		wsConn.SendCallback(modules.Packet{Code: 0}, pack)
	}
}

func suspend(pack modules.Packet, wsConn *common.Conn) {
	err := basic.Suspend()
	if err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
	} else {
		wsConn.SendCallback(modules.Packet{Code: 0}, pack)
	}
}

func restart(pack modules.Packet, wsConn *common.Conn) {
	err := basic.Restart()
	if err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
	} else {
		wsConn.SendCallback(modules.Packet{Code: 0}, pack)
	}
}

func shutdown(pack modules.Packet, wsConn *common.Conn) {
	err := basic.Shutdown()
	if err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
	} else {
		wsConn.SendCallback(modules.Packet{Code: 0}, pack)
	}
}

func screenshot(pack modules.Packet, wsConn *common.Conn) {
	var bridge string
	if val, ok := pack.GetData(`bridge`, reflect.String); !ok {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, pack)
		return
	} else {
		bridge = val.(string)
	}
	err := Screenshot.GetScreenshot(bridge)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
	}
}

func initTerminal(pack modules.Packet, wsConn *common.Conn) {
	telemetry.LogStructured("INFO", "[TERMINAL_INIT_HANDLER_START] Processing TERMINAL_INIT", map[string]interface{}{
		"event": pack.Event,
	})

	err := terminal.InitTerminal(pack)
	if err != nil {
		telemetry.LogStructured("ERROR", "[TERMINAL_INIT_HANDLER_FAILED] Terminal init failed", map[string]interface{}{
			"error": err.Error(),
		})
		wsConn.SendCallback(modules.Packet{Act: `TERMINAL_INIT`, Code: 1, Msg: err.Error()}, pack)
	} else {
		telemetry.LogStructured("INFO", "[TERMINAL_INIT_HANDLER_SUCCESS] Terminal init succeeded", nil)
		wsConn.SendCallback(modules.Packet{Act: `TERMINAL_INIT`, Code: 0}, pack)
	}
}

func inputTerminal(pack modules.Packet, wsConn *common.Conn) {
	terminal.InputTerminal(pack)
}

func resizeTerminal(pack modules.Packet, wsConn *common.Conn) {
	terminal.ResizeTerminal(pack)
}

func pingTerminal(pack modules.Packet, wsConn *common.Conn) {
	terminal.PingTerminal(pack)
}

func killTerminal(pack modules.Packet, wsConn *common.Conn) {
	terminal.KillTerminal(pack)
}

func listFiles(pack modules.Packet, wsConn *common.Conn) {
	path := `/`
	if val, ok := pack.GetData(`path`, reflect.String); ok {
		path = val.(string)
	}
	files, err := file.ListFiles(path)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
	} else {
		wsConn.SendCallback(modules.Packet{Code: 0, Data: smap{`files`: files}}, pack)
	}
}

func fetchFile(pack modules.Packet, wsConn *common.Conn) {
	var path, filename, bridge string
	if val, ok := pack.GetData(`path`, reflect.String); !ok {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|EXPLORER.FILE_OR_DIR_NOT_EXIST}`}, pack)
		return
	} else {
		path = val.(string)
	}
	if val, ok := pack.GetData(`file`, reflect.String); !ok {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, pack)
		return
	} else {
		filename = val.(string)
	}
	if val, ok := pack.GetData(`bridge`, reflect.String); !ok {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, pack)
		return
	} else {
		bridge = val.(string)
	}
	err := file.FetchFile(path, filename, bridge)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
	}
}

func removeFiles(pack modules.Packet, wsConn *common.Conn) {
	var files []string
	if val, ok := pack.Data[`files`]; !ok {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|EXPLORER.FILE_OR_DIR_NOT_EXIST}`}, pack)
		return
	} else {
		slice := val.([]any)
		for i := 0; i < len(slice); i++ {
			file, ok := slice[i].(string)
			if ok {
				files = append(files, file)
			}
		}
		if len(files) == 0 {
			wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|EXPLORER.FILE_OR_DIR_NOT_EXIST}`}, pack)
			return
		}
	}
	err := file.RemoveFiles(files)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
	} else {
		wsConn.SendCallback(modules.Packet{Code: 0}, pack)
	}
}

func mkdirFiles(pack modules.Packet, wsConn *common.Conn) {
	rawPath, ok := pack.GetData(`path`, reflect.String)
	if !ok || len(strings.TrimSpace(rawPath.(string))) == 0 {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, pack)
		return
	}
	if err := file.Mkdir(rawPath.(string)); err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
		return
	}
	wsConn.SendCallback(modules.Packet{Code: 0}, pack)
}

func moveFiles(pack modules.Packet, wsConn *common.Conn) {
	src, ok := pack.GetData(`src`, reflect.String)
	if !ok || len(strings.TrimSpace(src.(string))) == 0 {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, pack)
		return
	}
	dst, ok := pack.GetData(`dst`, reflect.String)
	if !ok || len(strings.TrimSpace(dst.(string))) == 0 {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, pack)
		return
	}
	if err := file.Move(src.(string), dst.(string)); err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
		return
	}
	wsConn.SendCallback(modules.Packet{Code: 0}, pack)
}

func copyFiles(pack modules.Packet, wsConn *common.Conn) {
	src, ok := pack.GetData(`src`, reflect.String)
	if !ok || len(strings.TrimSpace(src.(string))) == 0 {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, pack)
		return
	}
	dst, ok := pack.GetData(`dst`, reflect.String)
	if !ok || len(strings.TrimSpace(dst.(string))) == 0 {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, pack)
		return
	}
	if err := file.Copy(src.(string), dst.(string)); err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
		return
	}
	wsConn.SendCallback(modules.Packet{Code: 0}, pack)
}

func execFile(pack modules.Packet, wsConn *common.Conn) {
	rawPath, ok := pack.GetData(`path`, reflect.String)
	if !ok || len(strings.TrimSpace(rawPath.(string))) == 0 {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, pack)
		return
	}
	args := ""
	if rawArgs, exists := pack.Data[`args`]; exists {
		switch v := rawArgs.(type) {
		case string:
			args = v
		case []any:
			parts := make([]string, 0, len(v))
			for _, item := range v {
				if s, ok := item.(string); ok {
					parts = append(parts, s)
				}
			}
			if len(parts) > 0 {
				args = strings.Join(parts, " ")
			}
		}
	}
	workdir := ""
	if val, ok := pack.GetData(`workdir`, reflect.String); ok {
		workdir = val.(string)
	}
	pid, err := file.Exec(rawPath.(string), args, workdir)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Act: `FILE_EXEC`, Code: 1, Msg: err.Error()}, pack)
		return
	}
	wsConn.SendCallback(modules.Packet{Act: `FILE_EXEC`, Code: 0, Data: map[string]any{
		`pid`: pid,
	}}, pack)
}

func uploadFiles(pack modules.Packet, wsConn *common.Conn) {
	var (
		start, end int64
		files      []string
		bridge     string
	)
	if val, ok := pack.Data[`files`]; !ok {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|EXPLORER.FILE_OR_DIR_NOT_EXIST}`}, pack)
		return
	} else {
		slice := val.([]any)
		for i := 0; i < len(slice); i++ {
			file, ok := slice[i].(string)
			if ok {
				files = append(files, file)
			}
		}
		if len(files) == 0 {
			wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|EXPLORER.FILE_OR_DIR_NOT_EXIST}`}, pack)
			return
		}
	}
	if val, ok := pack.GetData(`bridge`, reflect.String); !ok {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, pack)
		return
	} else {
		bridge = val.(string)
	}
	{
		if val, ok := pack.GetData(`start`, reflect.Float64); ok {
			start = int64(val.(float64))
		}
		if val, ok := pack.GetData(`end`, reflect.Float64); ok {
			end = int64(val.(float64))
			if end > 0 {
				end++
			}
		}
		if end > 0 && end < start {
			wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, pack)
			return
		}
	}
	err := file.UploadFiles(files, bridge, start, end)
	if err != nil {
		golog.Error(err)
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
	}
}

func uploadTextFile(pack modules.Packet, wsConn *common.Conn) {
	var path, bridge string
	if val, ok := pack.GetData(`file`, reflect.String); !ok {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|EXPLORER.FILE_OR_DIR_NOT_EXIST}`}, pack)
		return
	} else {
		path = val.(string)
	}
	if val, ok := pack.GetData(`bridge`, reflect.String); !ok {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, pack)
		return
	} else {
		bridge = val.(string)
	}
	err := file.UploadTextFile(path, bridge)
	if err != nil {
		golog.Error(err)
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
	}
}

func listProcesses(pack modules.Packet, wsConn *common.Conn) {
	processes, err := process.ListProcesses()
	if err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
	} else {
		wsConn.SendCallback(modules.Packet{Code: 0, Data: map[string]any{`processes`: processes}}, pack)
	}
}

func killProcess(pack modules.Packet, wsConn *common.Conn) {
	var (
		pid int32
		err error
	)
	if val, ok := pack.GetData(`pid`, reflect.Float64); !ok {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, pack)
		return
	} else {
		pid = int32(val.(float64))
	}
	err = process.KillProcess(int32(pid))
	if err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
	} else {
		wsConn.SendCallback(modules.Packet{Code: 0}, pack)
	}
}

func initDesktop(pack modules.Packet, wsConn *common.Conn) {
	telemetry.LogStructured("INFO", "[DESKTOP_INIT_HANDLER_START] Processing DESKTOP_INIT", map[string]interface{}{
		"event":   pack.Event,
		"desktop": pack.Data["desktop"],
	})

	err := desktop.InitDesktop(pack)
	if err != nil {
		telemetry.LogStructured("ERROR", "[DESKTOP_INIT_HANDLER_FAILED] Desktop init failed", map[string]interface{}{
			"error": err.Error(),
		})
		wsConn.SendCallback(modules.Packet{Act: `DESKTOP_INIT`, Code: 1, Msg: err.Error()}, pack)
	} else {
		telemetry.LogStructured("INFO", "[DESKTOP_INIT_HANDLER_SUCCESS] Desktop init succeeded", nil)
		// DO NOT send response here - desktop.InitDesktop already sends DESKTOP_INIT
		// with resolution data (width, height, monitors) via sendDesktopPacket.
		// Sending another response without this data would cause the browser to
		// miss the resolution info and fail to size the canvas properly.
	}
}

func pingDesktop(pack modules.Packet, wsConn *common.Conn) {
	desktop.PingDesktop(pack)
}

func killDesktop(pack modules.Packet, wsConn *common.Conn) {
	desktop.KillDesktop(pack)
}

func getDesktop(pack modules.Packet, wsConn *common.Conn) {
	desktop.GetDesktop(pack)
}

func inputDesktop(pack modules.Packet, wsConn *common.Conn) {
	err := desktop.HandleInput(pack)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Act: `DESKTOP_INPUT`, Code: 1, Msg: err.Error()}, pack)
		return
	}
	wsConn.SendCallback(modules.Packet{Act: `DESKTOP_INPUT`, Code: 0}, pack)
}

func configDesktop(pack modules.Packet, wsConn *common.Conn) {
	err := desktop.HandleConfig(pack)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Act: `DESKTOP_CONFIG`, Code: 1, Msg: err.Error()}, pack)
		return
	}
	wsConn.SendCallback(modules.Packet{Act: `DESKTOP_CONFIG`, Code: 0}, pack)
}

func codecDesktop(pack modules.Packet, wsConn *common.Conn) {
	err := desktop.HandleCodec(pack)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Act: `DESKTOP_CODEC`, Code: 1, Msg: err.Error()}, pack)
		return
	}
	wsConn.SendCallback(modules.Packet{Act: `DESKTOP_CODEC`, Code: 0}, pack)
}

func clipboardDesktop(pack modules.Packet, wsConn *common.Conn) {
	err := desktop.HandleClipboard(pack)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Act: `DESKTOP_CLIPBOARD`, Code: 1, Msg: err.Error()}, pack)
		return
	}
	wsConn.SendCallback(modules.Packet{Act: `DESKTOP_CLIPBOARD`, Code: 0}, pack)
}

func fileDropDesktop(pack modules.Packet, wsConn *common.Conn) {
	err := desktop.HandleFileDrop(pack)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Act: `DESKTOP_FILE_DROP`, Code: 1, Msg: err.Error()}, pack)
		return
	}
	wsConn.SendCallback(modules.Packet{Act: `DESKTOP_FILE_DROP`, Code: 0}, pack)
}

func audioDesktop(pack modules.Packet, wsConn *common.Conn) {
	err := desktop.HandleAudio(pack)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Act: `DESKTOP_AUDIO`, Code: 1, Msg: err.Error()}, pack)
		return
	}
	wsConn.SendCallback(modules.Packet{Act: `DESKTOP_AUDIO`, Code: 0}, pack)
}

func execCommand(pack modules.Packet, wsConn *common.Conn) {
	var proc *exec.Cmd
	var cmd, args string
	if val, ok := pack.Data[`cmd`]; !ok {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, pack)
		return
	} else {
		cmd = val.(string)
	}
	if val, ok := pack.Data[`args`]; !ok {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, pack)
		return
	} else {
		args = val.(string)
	}
	if len(args) == 0 {
		proc = exec.Command(cmd)
	} else {
		proc = exec.Command(cmd, strings.Split(args, ` `)...)
	}
	err := proc.Start()
	if err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
	} else {
		wsConn.SendCallback(modules.Packet{Code: 0, Data: map[string]any{
			`pid`: proc.Process.Pid,
		}}, pack)
		proc.Process.Release()
	}
}

func webrtcUnsupported(pack modules.Packet, wsConn *common.Conn) {
	wsConn.SendCallback(modules.Packet{
		Act:  pack.Act,
		Code: 1,
		Msg:  `${i18n|DESKTOP.UNSUPPORTED_PLATFORM}`,
	}, pack)
}

func webrtcOffer(pack modules.Packet, wsConn *common.Conn) {
	resp, err := desktop.HandleWebRTCOffer(pack)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Act: pack.Act, Code: 1, Msg: err.Error()}, pack)
		return
	}
	wsConn.SendCallback(modules.Packet{Act: pack.Act, Code: 0, Data: resp}, pack)
}

func webrtcAnswer(pack modules.Packet, wsConn *common.Conn) {
	if err := desktop.HandleWebRTCAnswer(pack); err != nil {
		wsConn.SendCallback(modules.Packet{Act: pack.Act, Code: 1, Msg: err.Error()}, pack)
		return
	}
	wsConn.SendCallback(modules.Packet{Act: pack.Act, Code: 0}, pack)
}

func webrtcICE(pack modules.Packet, wsConn *common.Conn) {
	if err := desktop.HandleWebRTCIce(pack); err != nil {
		wsConn.SendCallback(modules.Packet{Act: pack.Act, Code: 1, Msg: err.Error()}, pack)
		return
	}
	wsConn.SendCallback(modules.Packet{Act: pack.Act, Code: 0}, pack)
}

func inputRawTerminal(pack []byte, event string) {
	terminal.InputRawTerminal(pack, event)
}

// Webcam handlers
func listWebcams(pack modules.Packet, wsConn *common.Conn) {
	devices, err := webcam.ListDevices()
	if err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
	} else {
		wsConn.SendCallback(modules.Packet{Code: 0, Data: map[string]any{`devices`: devices}}, pack)
	}
}

func initWebcam(pack modules.Packet, wsConn *common.Conn) {
	err := webcam.InitWebcam(pack)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Act: `WEBCAM_INIT`, Code: 1, Msg: err.Error()}, pack)
	} else {
		wsConn.SendCallback(modules.Packet{Act: `WEBCAM_INIT`, Code: 0}, pack)
	}
}

func pingWebcam(pack modules.Packet, wsConn *common.Conn) {
	webcam.PingWebcam(pack)
}

func killWebcam(pack modules.Packet, wsConn *common.Conn) {
	webcam.KillWebcam(pack)
}

// handleRedirect updates runtime controller target and forces a reconnect.
func handleRedirect(pack modules.Packet, wsConn *common.Conn) {
	targetVal, ok := pack.Data[`target`]
	if !ok {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: "redirect target missing"}, pack)
		return
	}
	target, ok := targetVal.(string)
	if !ok || target == "" {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: "redirect target invalid"}, pack)
		return
	}

	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: "redirect parse failed"}, pack)
		return
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" || u.Scheme == "wss" {
			port = "443"
		} else {
			port = "80"
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: "redirect port invalid"}, pack)
		return
	}

	secure := u.Scheme == "https" || u.Scheme == "wss"
	path := strings.TrimSuffix(u.EscapedPath(), `/`)

	// Apply new target for subsequent connection attempts.
	config.Config.Host = host
	config.Config.Port = p
	config.Config.Secure = secure
	if path != "" {
		config.Config.Path = path
	}

	golog.Infof("redirect: switching controller to %s (secure=%v path=%s)", target, secure, config.Config.Path)
	wsConn.SendCallback(modules.Packet{Code: 0, Act: `REDIRECT`}, pack)

	// Close current connection to trigger reconnect loop.
	common.Mutex.Lock()
	if common.WSConn != nil {
		_ = common.WSConn.Close()
		common.WSConn = nil
	}
	common.Mutex.Unlock()
}

func selectWebcam(pack modules.Packet, wsConn *common.Conn) {
	err := webcam.HandleSelect(pack)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Act: `WEBCAM_SELECT`, Code: 1, Msg: err.Error()}, pack)
		return
	}
	wsConn.SendCallback(modules.Packet{Act: `WEBCAM_SELECT`, Code: 0}, pack)
}

// Audio handlers
func listAudioDevices(pack modules.Packet, wsConn *common.Conn) {
	devices, err := audio.ListDevices()
	if err != nil {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: err.Error()}, pack)
	} else {
		wsConn.SendCallback(modules.Packet{Code: 0, Data: map[string]any{`devices`: devices}}, pack)
	}
}

func initAudio(pack modules.Packet, wsConn *common.Conn) {
	err := audio.InitAudio(pack)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Act: `AUDIO_INIT`, Code: 1, Msg: err.Error()}, pack)
	} else {
		wsConn.SendCallback(modules.Packet{Act: `AUDIO_INIT`, Code: 0}, pack)
	}
}

func pingAudio(pack modules.Packet, wsConn *common.Conn) {
	audio.PingAudio(pack)
}

func killAudio(pack modules.Packet, wsConn *common.Conn) {
	audio.KillAudio(pack)
}

func selectAudio(pack modules.Packet, wsConn *common.Conn) {
	err := audio.HandleSelect(pack)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Act: `AUDIO_SELECT`, Code: 1, Msg: err.Error()}, pack)
		return
	}
	wsConn.SendCallback(modules.Packet{Act: `AUDIO_SELECT`, Code: 0}, pack)
}
