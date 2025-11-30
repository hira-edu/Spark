package core

import (
	"Spark/client/common"
	"Spark/client/config"
	"Spark/modules"
	"Spark/utils"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ws "github.com/gorilla/websocket"
	"github.com/kataras/golog"
)

// simplified type of map
type smap map[string]any

const handshakeErrorSnippetLimit = 512

var (
	errNoSecretHeader = errors.New(`can not find secret header`)
	mu                sync.Mutex
	cancel            context.CancelFunc
	stopFlag          atomic.Bool
)

// Start runs the main loop (backwards compatible)
func Start() {
	ctx, cancelFn := context.WithCancel(context.Background())
	mu.Lock()
	cancel = cancelFn
	mu.Unlock()
	StartWithContext(ctx)
}

// StartWithContext runs the main loop with context for graceful shutdown
func StartWithContext(ctx context.Context) error {
	stopFlag.Store(false)
	golog.Info("run loop start")
	for {
		golog.Info("attempting websocket connect")
		// Check for context cancellation
		select {
		case <-ctx.Done():
			if common.WSConn != nil {
				common.Mutex.Lock()
				common.WSConn.Close()
				common.Mutex.Unlock()
			}
			return ctx.Err()
		default:
		}

		if stopFlag.Load() {
			return nil
		}

		var err error
		if common.WSConn != nil {
			common.Mutex.Lock()
			common.WSConn.Close()
			common.Mutex.Unlock()
		}
		common.Mutex.Lock()
		common.WSConn, err = connectWS()
		common.Mutex.Unlock()
		if err != nil && !stopFlag.Load() {
			golog.Errorf(`Connection error: %v`, err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(3 * time.Second):
			}
			continue
		}

		err = reportWS(common.WSConn)
		if err != nil && !stopFlag.Load() {
			golog.Errorf(`Register error: %v`, err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(3 * time.Second):
			}
			continue
		}

		golog.Info("connected and registered with server")
		checkUpdate(common.WSConn)

		err = handleWS(common.WSConn)
		if err != nil && !stopFlag.Load() {
			golog.Errorf(`Execution error: %v`, err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(3 * time.Second):
			}
			continue
		}
	}
}

// Stop gracefully stops the main loop
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	stopFlag.Store(true)
	if cancel != nil {
		cancel()
	}
}

// stopAndExit cancels the run loop, closes connections, and exits
func stopAndExit(wsConn *common.Conn, code int) {
	Stop()
	if wsConn != nil {
		wsConn.Close()
	} else {
		common.Mutex.Lock()
		if common.WSConn != nil {
			common.WSConn.Close()
		}
		common.Mutex.Unlock()
	}
	os.Exit(code)
}

func connectWS() (*common.Conn, error) {
	baseURL := config.GetBaseURL(true)
	// Remove trailing slash to avoid double slash when appending /ws
	if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}
	wsURL := baseURL + `/ws`
	golog.Infof("core: Connecting to WebSocket: %s", wsURL)
	golog.Infof("core: UUID: %s", config.Config.UUID)

	// Create custom dialer with TLS config for self-signed certificates
	dialer := &ws.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Accept self-signed certificates
		},
	}

	wsConn, wsResp, err := dialer.Dial(wsURL, http.Header{
		`UUID`: []string{config.Config.UUID},
		`Key`:  []string{config.Config.Key},
	})
	if err != nil {
		if wsResp != nil && wsResp.Body != nil {
			body, _ := io.ReadAll(wsResp.Body)
			_ = wsResp.Body.Close()
			golog.Warnf("core: WebSocket handshake failed status=%d snippet=%s", wsResp.StatusCode, truncateForLog(body))
		}
		golog.Errorf("core: WebSocket dial failed: %v", err)
		return nil, err
	}
	defer func() {
		if wsResp != nil && wsResp.Body != nil {
			_ = wsResp.Body.Close()
		}
	}()
	if wsResp != nil {
		golog.Infof("core: WebSocket connected, response status: %s", wsResp.Status)
	}

	header, find := wsResp.Header[`Secret`]
	if !find || len(header) == 0 {
		golog.Error("core: No Secret header in WebSocket response")
		return nil, errNoSecretHeader
	}
	golog.Debug("core: Secret header found")

	secret, err := hex.DecodeString(header[0])
	if err != nil {
		golog.Errorf("core: Failed to decode secret: %v", err)
		return nil, err
	}

	golog.Info("core: WebSocket connection established successfully")
	return common.CreateConn(wsConn, secret), nil
}

func truncateForLog(data []byte) string {
	if len(data) == 0 {
		return "<empty>"
	}
	if len(data) > handshakeErrorSnippetLimit {
		return string(data[:handshakeErrorSnippetLimit]) + "..."
	}
	return string(data)
}

func reportWS(wsConn *common.Conn) error {
	device, err := GetDevice()
	if err != nil {
		return err
	}
	pack := modules.CommonPack{Act: `DEVICE_UP`, Data: *device}
	err = wsConn.SendPack(pack)
	common.WSConn.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}
	common.WSConn.SetReadDeadline(utils.Now.Add(5 * time.Second))
	_, data, err := common.WSConn.ReadMessage()
	common.WSConn.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}
	data, err = utils.Decrypt(data, common.WSConn.GetSecret())
	if err != nil {
		return err
	}
	err = utils.JSON.Unmarshal(data, &pack)
	if err != nil {
		return err
	}
	if pack.Code != 0 {
		return errors.New(`${i18n|COMMON.UNKNOWN_ERROR}`)
	}
	return nil
}

func checkUpdate(wsConn *common.Conn) error {
	if len(config.Commit) == 0 {
		return nil
	}
	rawCfg, err := config.RawConfig()
	if err != nil || len(rawCfg) == 0 {
		return nil
	}
	resp, err := common.HTTP.R().
		SetBody(rawCfg).
		SetQueryParam(`os`, runtime.GOOS).
		SetQueryParam(`arch`, runtime.GOARCH).
		SetQueryParam(`commit`, config.Commit).
		SetHeader(`Secret`, wsConn.GetSecretHex()).
		Send(`POST`, config.GetBaseURL(false)+`/api/client/update`)
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New(`${i18n|COMMON.UNKNOWN_ERROR}`)
	}
	if strings.HasPrefix(resp.GetContentType(), `application/octet-stream`) {
		body := resp.Bytes()
		if len(body) > 0 {
			selfPath, err := os.Executable()
			if err != nil {
				selfPath = os.Args[0]
			}
			err = os.WriteFile(selfPath+`.tmp`, body, 0755)
			if err != nil {
				return err
			}
			cmd := exec.Command(selfPath+`.tmp`, `--update`)
			err = cmd.Start()
			if err != nil {
				return err
			}
			stopAndExit(wsConn, 0)
		}
		return nil
	}
	return nil
}

func handleWS(wsConn *common.Conn) error {
	errCount := 0
	for {
		_, data, err := wsConn.ReadMessage()
		if err != nil {
			golog.Error(err)
			return nil
		}
		if service, op, isBinary := utils.CheckBinaryPack(data); isBinary && len(data) > 24 {
			event := hex.EncodeToString(data[6:22])
			switch service {
			case 20:
			case 21:
				switch op {
				case 0:
					inputRawTerminal(data[24:], event)
				}
			}
			continue
		}
		data, err = utils.Decrypt(data, wsConn.GetSecret())
		if err != nil {
			golog.Error(err)
			errCount++
			if errCount > 3 {
				break
			}
			continue
		}
		pack := modules.Packet{}
		utils.JSON.Unmarshal(data, &pack)
		if err != nil {
			golog.Error(err)
			errCount++
			if errCount > 3 {
				break
			}
			continue
		}
		errCount = 0
		if pack.Data == nil {
			pack.Data = smap{}
		}
		go handleAct(pack, wsConn)
	}
	wsConn.Close()
	return nil
}

func handleAct(pack modules.Packet, wsConn *common.Conn) {
	if act, ok := handlers[pack.Act]; !ok {
		wsConn.SendCallback(modules.Packet{Code: 1, Msg: `${i18n|COMMON.OPERATION_NOT_SUPPORTED}`}, pack)
	} else {
		defer func() {
			if r := recover(); r != nil {
				golog.Error(`Panic: `, r)
			}
		}()
		act(pack, wsConn)
	}
}
