package core

import (
	"Spark/client/common"
	"Spark/client/config"
	"Spark/client/telemetry"
	"Spark/modules"
	"Spark/utils"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
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

	// Reconnection and circuit breaker
	reconnectStrategy *telemetry.ReconnectStrategy
	circuitBreaker    *telemetry.CircuitBreaker
	connectionStart   time.Time
	lastHeartbeat     time.Time
	heartbeatMu       sync.RWMutex
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

	// Initialize reconnection strategy and circuit breaker
	reconnectStrategy = telemetry.NewReconnectStrategy(
		1*time.Second,  // base backoff
		60*time.Second, // max backoff
		0.2,            // ±20% jitter
	)
	circuitBreaker = telemetry.NewCircuitBreaker(
		"websocket",     // name
		10,              // 10 failures -> open
		3,               // 3 successes -> close from half_open
		5*time.Minute,   // wait 5 minutes before retry
	)

	golog.Info("run loop start")
	telemetry.LogWSEvent("core started", map[string]interface{}{
		"version": config.Commit,
	})

	for {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			if common.WSConn != nil {
				common.Mutex.Lock()
				common.WSConn.Close()
				common.Mutex.Unlock()
			}
			telemetry.LogWSEvent("core stopped", map[string]interface{}{
				"reason": ctx.Err().Error(),
			})
			return ctx.Err()
		default:
		}

		if stopFlag.Load() {
			telemetry.LogWSEvent("core stopped", map[string]interface{}{
				"reason": "stop flag set",
			})
			return nil
		}

		// Circuit breaker protection
		err := circuitBreaker.Call(func() error {
			return attemptConnection(ctx)
		})

		if err != nil && !stopFlag.Load() {
			telemetry.LogWSError("connection cycle failed", err, map[string]interface{}{
				"circuit_breaker_state": circuitBreaker.GetState(),
			})

			// Determine backoff based on circuit breaker state
			var backoff time.Duration
			if circuitBreaker.IsOpen() {
				// Long backoff when circuit breaker is open
				backoff = 30 * time.Second
				telemetry.LogWSEvent("circuit breaker open, long backoff", map[string]interface{}{
					"backoff_seconds": 30,
				})
			} else {
				// Exponential backoff with jitter
				backoff = reconnectStrategy.NextBackoff()
				telemetry.WSReconnectAttempts.Inc()
				telemetry.LogWSEvent("exponential backoff", map[string]interface{}{
					"backoff_seconds": backoff.Seconds(),
					"attempt":         reconnectStrategy.GetAttempt(),
				})
			}

			// Wait with context cancellation support
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			continue
		}

		// Success - reset backoff strategy
		reconnectStrategy.Reset()
	}
}

// attemptConnection performs a single connection attempt (connect + register + handle)
func attemptConnection(ctx context.Context) error {
	telemetry.LogWSEvent("attempting connection", nil)
	telemetry.WSConnectionsTotal.Inc()

	// Close existing connection if any
	common.Mutex.Lock()
	if common.WSConn != nil {
		common.WSConn.Close()
	}
	common.Mutex.Unlock()

	// Check for cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Connect using transport fallback if any fallback transports are enabled
	var wsConn *common.Conn
	var err error
	hasFallback := config.Config.EnableQUIC || config.Config.EnableLongPoll || config.Config.EnableDNS
	if hasFallback {
		wsConn, err = connectWithAutoFallback(ctx)
	} else {
		wsConn, err = connectWS()
	}
	if err != nil {
		telemetry.LogWSError("connect failed", err, nil)
		return categorizeError(fmt.Errorf("connect: %w", err))
	}

	common.Mutex.Lock()
	common.WSConn = wsConn
	common.Mutex.Unlock()

	// Record connection established
	connectionStart = time.Now()
	telemetry.GetHealth().SetWSConnected(true)

	// Register
	err = reportWS(wsConn)
	if err != nil {
		telemetry.LogWSError("register failed", err, nil)
		telemetry.GetHealth().SetWSConnected(false)
		return fmt.Errorf("register: %w", err)
	}

	telemetry.LogWSEvent("connected and registered", nil)
	checkUpdate(wsConn)

	// Handle messages (blocks until disconnect)
	err = handleWS(wsConn)

	// Record disconnection
	duration := time.Since(connectionStart)
	telemetry.WSConnectionDuration.Observe(duration.Seconds())
	telemetry.GetHealth().SetWSConnected(false)

	if err != nil {
		telemetry.LogWSError("handle failed", err, map[string]interface{}{
			"connection_duration_seconds": duration.Seconds(),
		})
		return fmt.Errorf("handle: %w", err)
	}

	return nil
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
	heartbeatMu.Lock()
	lastHeartbeat = time.Now()
	heartbeatMu.Unlock()
	telemetry.GetHealth().SetHeartbeat()

	// Set read deadline to detect network black holes
	wsConn.SetReadDeadline(time.Now().Add(90 * time.Second))

	for {
		// Refresh read deadline on each iteration
		wsConn.SetReadDeadline(time.Now().Add(90 * time.Second))

		_, data, err := wsConn.ReadMessage()
		if err != nil {
			// Extract close reason for diagnostics
			if ws.IsCloseError(err,
				ws.CloseNormalClosure,
				ws.CloseGoingAway,
				ws.CloseProtocolError,
				ws.CloseUnsupportedData,
				ws.CloseNoStatusReceived,
				ws.CloseAbnormalClosure,
				ws.CloseInvalidFramePayloadData,
				ws.ClosePolicyViolation,
				ws.CloseMessageTooBig,
				ws.CloseMandatoryExtension,
				ws.CloseInternalServerErr,
				ws.CloseServiceRestart,
				ws.CloseTryAgainLater,
				ws.CloseTLSHandshake) {

				closeErr := err.(*ws.CloseError)
				closeCode := strconv.Itoa(closeErr.Code)
				closeReason := closeErr.Text
				if closeReason == "" {
					closeReason = getCloseReasonDescription(closeErr.Code)
				}

				// Get time since last heartbeat
				heartbeatMu.RLock()
				heartbeatAge := time.Since(lastHeartbeat)
				heartbeatMu.RUnlock()

				telemetry.WSDisconnectsTotal.WithLabelValues(closeReason, closeCode).Inc()
				telemetry.LogWSError("closed by server", err, map[string]interface{}{
					"close_code":             closeCode,
					"close_reason":           closeReason,
					"last_heartbeat_seconds": heartbeatAge.Seconds(),
				})

				// Special handling for abnormal closes (1005, 1006)
				if closeErr.Code == ws.CloseNoStatusReceived || closeErr.Code == ws.CloseAbnormalClosure {
					telemetry.LogWSEvent("abnormal close detected", map[string]interface{}{
						"code":                   closeErr.Code,
						"last_heartbeat_seconds": heartbeatAge.Seconds(),
						"possible_causes":        "server timeout, network issue, auth failure, or server crash",
					})
				}
			} else {
				// Network or other error
				telemetry.LogWSError("read error", err, nil)
				telemetry.WSDisconnectsTotal.WithLabelValues("network_error", "0").Inc()
			}

			wsConn.Close()
			return err
		}

		// Update heartbeat on every message received
		heartbeatMu.Lock()
		lastHeartbeat = time.Now()
		heartbeatMu.Unlock()
		telemetry.GetHealth().SetHeartbeat()

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
			telemetry.LogWSError("decrypt failed", err, nil)
			errCount++
			if errCount > 3 {
				telemetry.LogWSEvent("too many decrypt errors, disconnecting", map[string]interface{}{
					"error_count": errCount,
				})
				break
			}
			continue
		}

		pack := modules.Packet{}
		err = utils.JSON.Unmarshal(data, &pack)
		if err != nil {
			telemetry.LogWSError("unmarshal failed", err, nil)
			errCount++
			if errCount > 3 {
				telemetry.LogWSEvent("too many unmarshal errors, disconnecting", map[string]interface{}{
					"error_count": errCount,
				})
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

// getCloseReasonDescription returns a human-readable description of close codes
func getCloseReasonDescription(code int) string {
	switch code {
	case ws.CloseNormalClosure:
		return "normal_closure"
	case ws.CloseGoingAway:
		return "going_away"
	case ws.CloseProtocolError:
		return "protocol_error"
	case ws.CloseUnsupportedData:
		return "unsupported_data"
	case ws.CloseNoStatusReceived:
		return "no_status_received"
	case ws.CloseAbnormalClosure:
		return "abnormal_closure"
	case ws.CloseInvalidFramePayloadData:
		return "invalid_payload"
	case ws.ClosePolicyViolation:
		return "policy_violation"
	case ws.CloseMessageTooBig:
		return "message_too_big"
	case ws.CloseMandatoryExtension:
		return "mandatory_extension"
	case ws.CloseInternalServerErr:
		return "internal_server_error"
	case ws.CloseServiceRestart:
		return "service_restart"
	case ws.CloseTryAgainLater:
		return "try_again_later"
	case ws.CloseTLSHandshake:
		return "tls_handshake_failed"
	default:
		return fmt.Sprintf("unknown_%d", code)
	}
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

// categorizeError wraps errors with categorization hints for circuit breaker
// Permanent errors should open circuit immediately
// Transient errors count toward threshold
type errorCategory int

const (
	errorTransient  errorCategory = iota // Network issues, timeouts
	errorPermanent                       // Auth failures, 401/403
	errorServer                          // Server errors, 500s
)

type categorizedError struct {
	err      error
	category errorCategory
}

func (e *categorizedError) Error() string {
	return e.err.Error()
}

func (e *categorizedError) Unwrap() error {
	return e.err
}

// categorizeError analyzes error and assigns category
func categorizeError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Permanent errors (auth, config, bad credentials)
	if strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "403") ||
		strings.Contains(errStr, "Unauthorized") ||
		strings.Contains(errStr, "Forbidden") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "bad credentials") ||
		err == errNoSecretHeader {
		return &categorizedError{err: err, category: errorPermanent}
	}

	// Server errors
	if strings.Contains(errStr, "500") ||
		strings.Contains(errStr, "502") ||
		strings.Contains(errStr, "503") ||
		strings.Contains(errStr, "504") ||
		strings.Contains(errStr, "Internal Server Error") {
		return &categorizedError{err: err, category: errorServer}
	}

	// Default: transient (network, timeout, etc.)
	return &categorizedError{err: err, category: errorTransient}
}

// isPermanentError checks if error is permanent
func isPermanentError(err error) bool {
	var catErr *categorizedError
	if errors.As(err, &catErr) {
		return catErr.category == errorPermanent
	}
	return false
}
