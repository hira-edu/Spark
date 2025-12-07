//go:build windows

package terminal

import (
	"Rocket/client/common"
	"Rocket/client/telemetry"
	"Rocket/modules"
	"Rocket/utils"
	"Rocket/utils/cmap"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	windows "golang.org/x/sys/windows"
)

// handleIO wraps a Windows handle for direct ReadFile/WriteFile operations.
// This is required because os.NewFile() doesn't work correctly with Windows
// anonymous pipe handles - it causes Read() to block indefinitely.
// Based on: https://github.com/UserExistsError/conpty
type handleIO struct {
	handle windows.Handle
}

func (h *handleIO) Read(p []byte) (int, error) {
	if h.handle == 0 || h.handle == windows.InvalidHandle {
		return 0, errors.New("invalid handle")
	}
	var numRead uint32 = 0
	err := windows.ReadFile(h.handle, p, &numRead, nil)
	return int(numRead), err
}

func (h *handleIO) Write(p []byte) (int, error) {
	if h.handle == 0 || h.handle == windows.InvalidHandle {
		return 0, errors.New("invalid handle")
	}
	var numWritten uint32 = 0
	err := windows.WriteFile(h.handle, p, &numWritten, nil)
	return int(numWritten), err
}

func (h *handleIO) Close() error {
	if h.handle != 0 && h.handle != windows.InvalidHandle {
		err := windows.CloseHandle(h.handle)
		h.handle = windows.InvalidHandle
		return err
	}
	return nil
}

var (
	kernel32                          = syscall.NewLazyDLL("kernel32.dll")
	procCreatePseudoConsole           = kernel32.NewProc("CreatePseudoConsole")
	procResizePseudoConsole           = kernel32.NewProc("ResizePseudoConsole")
	procClosePseudoConsole            = kernel32.NewProc("ClosePseudoConsole")
	procInitializeProcThreadAttrList  = kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute     = kernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList = kernel32.NewProc("DeleteProcThreadAttributeList")
)

const (
	PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016
	EXTENDED_STARTUPINFO_PRESENT        = 0x00080000
)

type COORD struct {
	X int16
	Y int16
}

type terminal struct {
	lastPack   int64
	rawEvent   []byte
	escape     bool
	event      string
	cmd        *exec.Cmd
	procHandle windows.Handle
	hPC        uintptr    // Pseudo Console handle
	ptyIn      *handleIO  // For writing to ConPTY (uses windows.WriteFile)
	ptyOut     *handleIO  // For reading from ConPTY (uses windows.ReadFile)
	stdin      io.WriteCloser
	stdout     io.ReadCloser
	useLegacy  bool // fallback to pipes if ConPTY not available
	mu         sync.Mutex
}

var terminals = cmap.New[*terminal]()
var defaultCmd = ``
var conPTYSupported = false

func init() {
	defer func() {
		recover()
	}()
	// Set console code page to UTF-8
	kernel32.NewProc(`SetConsoleCP`).Call(65001)
	kernel32.NewProc(`SetConsoleOutputCP`).Call(65001)

	// Check if ConPTY is supported (Windows 10 1809+)
	conPTYSupported = procCreatePseudoConsole.Find() == nil

	go healthCheck()
}

func createPseudoConsole(cols, rows int16) (hPC uintptr, ptyIn, ptyOut *handleIO, err error) {
	// Create pipes for PTY using Windows API
	// Based on: https://github.com/UserExistsError/conpty
	var hPipeInRead, hPipeInWrite windows.Handle
	var hPipeOutRead, hPipeOutWrite windows.Handle

	// First pipe: for input to the pseudo console
	// ptyIn (write end) -> hPipeInRead (ConPTY reads from here)
	if err := windows.CreatePipe(&hPipeInRead, &hPipeInWrite, nil, 0); err != nil {
		return 0, nil, nil, err
	}

	// Second pipe: for output from the pseudo console
	// hPipeOutWrite (ConPTY writes here) -> ptyOut (read end)
	if err := windows.CreatePipe(&hPipeOutRead, &hPipeOutWrite, nil, 0); err != nil {
		windows.CloseHandle(hPipeInRead)
		windows.CloseHandle(hPipeInWrite)
		return 0, nil, nil, err
	}

	// Create pseudo console with the pipe handles
	// ConPTY will read input from hPipeInRead and write output to hPipeOutWrite
	size := COORD{X: cols, Y: rows}
	ret, _, _ := procCreatePseudoConsole.Call(
		uintptr(*(*int32)(unsafe.Pointer(&size))),
		uintptr(hPipeInRead),
		uintptr(hPipeOutWrite),
		0,
		uintptr(unsafe.Pointer(&hPC)),
	)
	if ret != 0 {
		windows.CloseHandle(hPipeInRead)
		windows.CloseHandle(hPipeInWrite)
		windows.CloseHandle(hPipeOutRead)
		windows.CloseHandle(hPipeOutWrite)
		return 0, nil, nil, errors.New("failed to create pseudo console")
	}

	// Close the handles that are now owned by the pseudo console
	// ConPTY duplicates these internally, so we close our copies
	windows.CloseHandle(hPipeInRead)
	windows.CloseHandle(hPipeOutWrite)

	// Return handleIO wrappers that use direct Windows ReadFile/WriteFile
	// This is the key fix - os.NewFile() doesn't work correctly for pipe handles
	ptyIn = &handleIO{handle: hPipeInWrite}
	ptyOut = &handleIO{handle: hPipeOutRead}

	return hPC, ptyIn, ptyOut, nil
}

func startConPTYShell(session *terminal) error {
	attrList, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return err
	}
	defer attrList.Delete()

	h := windows.Handle(session.hPC)
	if err := attrList.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, unsafe.Pointer(&h), unsafe.Sizeof(h)); err != nil {
		return err
	}

	var si windows.StartupInfoEx
	si.Cb = uint32(unsafe.Sizeof(si))
	si.StartupInfo.Flags = windows.STARTF_USESHOWWINDOW
	si.StartupInfo.ShowWindow = windows.SW_HIDE
	si.ProcThreadAttributeList = attrList.List()

	cmdLine := windows.StringToUTF16(getTerminal())
	pi := new(windows.ProcessInformation)
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	if err := windows.CreateProcess(nil, &cmdLine[0], nil, nil, false, flags, nil, nil, &si.StartupInfo, pi); err != nil {
		return err
	}
	windows.CloseHandle(pi.Thread)
	session.procHandle = pi.Process
	runtime.KeepAlive(cmdLine)
	return nil
}

func InitTerminal(pack modules.Packet) error {
	telemetry.LogStructured("INFO", "[TERMINAL_INIT] Starting terminal initialization", map[string]interface{}{
		"event":           pack.Event,
		"conPTYSupported": conPTYSupported,
	})

	// Validate and decode event UUID
	rawEvent, err := hex.DecodeString(pack.Event)
	if err != nil {
		telemetry.LogStructured("ERROR", "[TERMINAL_INIT] Failed to decode event UUID", map[string]interface{}{
			"event": pack.Event,
			"error": err.Error(),
		})
		return fmt.Errorf("invalid event UUID: %w", err)
	}
	if len(rawEvent) != 16 {
		telemetry.LogStructured("ERROR", "[TERMINAL_INIT] Invalid event UUID length", map[string]interface{}{
			"event":  pack.Event,
			"length": len(rawEvent),
		})
		return errors.New("event UUID must be 16 bytes")
	}

	session := &terminal{
		event:    pack.Event,
		escape:   false,
		rawEvent: rawEvent,
		lastPack: utils.Unix,
	}

	// Try ConPTY first (Windows 10 1809+)
	if conPTYSupported {
		telemetry.LogStructured("INFO", "[TERMINAL_INIT] Attempting ConPTY initialization", nil)
		hPC, ptyIn, ptyOut, err := createPseudoConsole(120, 30) // Default size
		if err == nil {
			session.hPC = hPC
			session.ptyIn = ptyIn
			session.ptyOut = ptyOut
			session.useLegacy = false

			shellCmd := getTerminal()
			telemetry.LogStructured("INFO", "[TERMINAL_INIT] Starting shell process", map[string]interface{}{
				"shell": shellCmd,
			})

			if err := startConPTYShell(session); err != nil {
				telemetry.LogStructured("WARN", "[TERMINAL_INIT] ConPTY shell start failed, falling back to legacy", map[string]interface{}{
					"error": err.Error(),
				})
				procClosePseudoConsole.Call(hPC)
				ptyIn.Close()
				ptyOut.Close()
				session.hPC = 0
				session.ptyIn = nil
				session.ptyOut = nil
			} else {
				terminalUUID := pack.Data[`terminal`].(string)
				terminals.Set(terminalUUID, session)
				telemetry.LogStructured("INFO", "[TERMINAL_INIT] ConPTY initialized successfully, starting reader goroutine", map[string]interface{}{
					"terminalUUID": terminalUUID,
					"procHandle":   fmt.Sprintf("0x%x", session.procHandle),
				})
				go readConPTY(session)
				return nil
			}
		} else {
			telemetry.LogStructured("WARN", "[TERMINAL_INIT] ConPTY creation failed, falling back to legacy", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Fallback to legacy pipe mode
	telemetry.LogStructured("INFO", "[TERMINAL_INIT] Using legacy pipe mode", nil)
	session.useLegacy = true
	shellCmd := getTerminal()
	cmd := exec.Command(shellCmd)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		telemetry.LogStructured("ERROR", "[TERMINAL_INIT] Failed to create stdout pipe", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		telemetry.LogStructured("ERROR", "[TERMINAL_INIT] Failed to create stderr pipe", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		telemetry.LogStructured("ERROR", "[TERMINAL_INIT] Failed to create stdin pipe", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	session.cmd = cmd
	session.stdin = stdin
	session.stdout = stdout

	readSender := func(rc io.ReadCloser, name string) {
		telemetry.LogStructured("INFO", "[TERMINAL_READ_LEGACY] Reader goroutine started", map[string]interface{}{
			"event":  session.event,
			"stream": name,
		})
		bufSize := 1024
		totalBytesRead := 0
		for !session.escape {
			buffer := make([]byte, bufSize)
			n, readErr := rc.Read(buffer)

			if n > 0 {
				totalBytesRead += n
				buffer = buffer[:n]
				session.lastPack = utils.Unix

				var sendErr error
				if n > 1024 {
					if bufSize < 32768 {
						bufSize *= 2
					}
					sendErr = common.WSConn.SendRawData(session.rawEvent, buffer, 21, 00)
				} else {
					bufSize = 1024
					jsonData, _ := utils.JSON.Marshal(modules.Packet{Act: `TERMINAL_OUTPUT`, Data: map[string]any{
						`output`: hex.EncodeToString(buffer),
					}})
					sendErr = common.WSConn.SendRawData(session.rawEvent, jsonData, 21, 01)
				}

				if sendErr != nil {
					telemetry.LogStructured("ERROR", "[TERMINAL_READ_LEGACY] Failed to send output", map[string]interface{}{
						"event":  session.event,
						"stream": name,
						"error":  sendErr.Error(),
					})
				}
			}

			if readErr != nil {
				telemetry.LogStructured("INFO", "[TERMINAL_READ_LEGACY] Stream closed", map[string]interface{}{
					"event":          session.event,
					"stream":         name,
					"totalBytesRead": totalBytesRead,
					"error":          readErr.Error(),
				})
				if !session.escape {
					session.escape = true
					doKillTerminal(session)
				}
				data, _ := utils.JSON.Marshal(modules.Packet{Act: `TERMINAL_QUIT`})
				common.WSConn.SendRawData(session.rawEvent, data, 21, 01)
				break
			}
		}
	}
	go readSender(stdout, "stdout")
	go readSender(stderr, "stderr")

	err = cmd.Start()
	if err != nil {
		telemetry.LogStructured("ERROR", "[TERMINAL_INIT] Failed to start shell", map[string]interface{}{
			"shell": shellCmd,
			"error": err.Error(),
		})
		session.escape = true
		return err
	}

	terminalUUID := pack.Data[`terminal`].(string)
	terminals.Set(terminalUUID, session)
	telemetry.LogStructured("INFO", "[TERMINAL_INIT] Legacy mode initialized successfully", map[string]interface{}{
		"terminalUUID": terminalUUID,
		"shell":        shellCmd,
		"pid":          cmd.Process.Pid,
	})
	return nil
}

func readConPTY(session *terminal) {
	telemetry.LogStructured("INFO", "[TERMINAL_READ] Reader goroutine started", map[string]interface{}{
		"event": session.event,
	})

	bufSize := 1024
	totalBytesRead := 0
	readCount := 0

	for !session.escape {
		buffer := make([]byte, bufSize)
		n, err := session.ptyOut.Read(buffer)
		readCount++

		// Handle read errors first
		if err != nil {
			telemetry.LogStructured("WARN", "[TERMINAL_READ] Read error, terminating session", map[string]interface{}{
				"event":          session.event,
				"error":          err.Error(),
				"totalBytesRead": totalBytesRead,
				"readCount":      readCount,
			})
			if !session.escape {
				session.escape = true
				doKillTerminal(session)
			}
			data, _ := utils.JSON.Marshal(modules.Packet{Act: `TERMINAL_QUIT`})
			if sendErr := common.WSConn.SendRawData(session.rawEvent, data, 21, 01); sendErr != nil {
				telemetry.LogStructured("ERROR", "[TERMINAL_READ] Failed to send QUIT packet", map[string]interface{}{
					"error": sendErr.Error(),
				})
			}
			break
		}

		// Skip if no data was read
		if n == 0 {
			continue
		}

		totalBytesRead += n
		buffer = buffer[:n]
		session.lastPack = utils.Unix

		// Log first successful read (helps debugging)
		if readCount == 1 || (readCount <= 5 && totalBytesRead < 1000) {
			telemetry.LogStructured("INFO", "[TERMINAL_READ] Data received from ConPTY", map[string]interface{}{
				"event":     session.event,
				"bytes":     n,
				"readCount": readCount,
				"preview":   truncateForLog(buffer, 50),
			})
		}

		// Send output to server
		var sendErr error
		if n > 1024 {
			// Large output: send as raw binary stream
			if bufSize < 32768 {
				bufSize *= 2
			}
			sendErr = common.WSConn.SendRawData(session.rawEvent, buffer, 21, 00)
		} else {
			// Normal output: send as JSON
			bufSize = 1024
			jsonData, _ := utils.JSON.Marshal(modules.Packet{Act: `TERMINAL_OUTPUT`, Data: map[string]any{
				`output`: hex.EncodeToString(buffer),
			}})
			sendErr = common.WSConn.SendRawData(session.rawEvent, jsonData, 21, 01)
		}

		if sendErr != nil {
			telemetry.LogStructured("ERROR", "[TERMINAL_READ] Failed to send terminal output", map[string]interface{}{
				"event": session.event,
				"error": sendErr.Error(),
				"bytes": n,
			})
		}
	}

	telemetry.LogStructured("INFO", "[TERMINAL_READ] Reader goroutine exiting", map[string]interface{}{
		"event":          session.event,
		"totalBytesRead": totalBytesRead,
		"readCount":      readCount,
	})
}

// truncateForLog truncates a byte slice for logging purposes
func truncateForLog(data []byte, maxLen int) string {
	if len(data) <= maxLen {
		return string(data)
	}
	return string(data[:maxLen]) + "..."
}

func InputRawTerminal(input []byte, uuid string) {
	session, ok := terminals.Get(uuid)
	if !ok {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.useLegacy {
		session.stdin.Write(input)
	} else if session.ptyIn != nil {
		session.ptyIn.Write(input)
	}
	session.lastPack = utils.Unix
}

func InputTerminal(pack modules.Packet) {
	var err error
	var uuid string
	var input []byte

	// Get and decode input
	inputVal, ok := pack.GetData(`input`, reflect.String)
	if !ok {
		return
	}
	if input, err = hex.DecodeString(inputVal.(string)); err != nil {
		return
	}

	// Get terminal UUID
	uuidVal, ok := pack.GetData(`terminal`, reflect.String)
	if !ok {
		return
	}
	uuid = uuidVal.(string)

	// Look up session (cmap.Get returns (*terminal, bool) directly)
	session, ok := terminals.Get(uuid)
	if !ok {
		return
	}

	// Write input to terminal
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.useLegacy {
		session.stdin.Write(input)
	} else if session.ptyIn != nil {
		session.ptyIn.Write(input)
	}
	session.lastPack = utils.Unix
}

func ResizeTerminal(pack modules.Packet) error {
	// Get cols
	colsVal, ok := pack.GetData(`cols`, reflect.Float64)
	if !ok {
		return errors.New("missing cols parameter")
	}
	cols := uint16(colsVal.(float64))

	// Get rows
	rowsVal, ok := pack.GetData(`rows`, reflect.Float64)
	if !ok {
		return errors.New("missing rows parameter")
	}
	rows := uint16(rowsVal.(float64))

	// Get terminal UUID
	uuidVal, ok := pack.GetData(`terminal`, reflect.String)
	if !ok {
		return errors.New("missing terminal parameter")
	}
	uuid := uuidVal.(string)

	// Look up session
	session, ok := terminals.Get(uuid)
	if !ok {
		return errors.New("terminal session not found")
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	// Only resize if using ConPTY
	if !session.useLegacy && session.hPC != 0 {
		size := COORD{X: int16(cols), Y: int16(rows)}
		ret, _, _ := procResizePseudoConsole.Call(
			session.hPC,
			uintptr(*(*int32)(unsafe.Pointer(&size))),
		)
		if ret != 0 {
			return errors.New("failed to resize pseudo console")
		}
	}
	// For legacy mode, resize is not supported (return nil to not break anything)
	return nil
}

func KillTerminal(pack modules.Packet) {
	var uuid string
	if val, ok := pack.GetData(`terminal`, reflect.String); !ok {
		return
	} else {
		uuid = val.(string)
	}
	session, ok := terminals.Get(uuid)
	if !ok {
		return
	}
	terminals.Remove(uuid)
	data, _ := utils.JSON.Marshal(modules.Packet{Act: `TERMINAL_QUIT`, Msg: `${i18n|TERMINAL.SESSION_CLOSED}`})
	common.WSConn.SendRawData(session.rawEvent, data, 21, 01)
	session.escape = true
	session.rawEvent = nil
	doKillTerminal(session)
}

func PingTerminal(pack modules.Packet) {
	var uuid string
	var session *terminal
	if val, ok := pack.GetData(`terminal`, reflect.String); !ok {
		return
	} else {
		uuid = val.(string)
	}
	session, ok := terminals.Get(uuid)
	if !ok {
		return
	}
	session.lastPack = utils.Unix
}

func doKillTerminal(terminal *terminal) {
	terminal.mu.Lock()
	defer terminal.mu.Unlock()

	terminal.escape = true

	if terminal.procHandle != 0 {
		_ = windows.TerminateProcess(terminal.procHandle, 0)
		windows.CloseHandle(terminal.procHandle)
		terminal.procHandle = 0
	}

	if !terminal.useLegacy {
		// ConPTY cleanup
		if terminal.hPC != 0 {
			procClosePseudoConsole.Call(terminal.hPC)
			terminal.hPC = 0
		}
		if terminal.ptyIn != nil {
			terminal.ptyIn.Close()
			terminal.ptyIn = nil
		}
		if terminal.ptyOut != nil {
			terminal.ptyOut.Close()
			terminal.ptyOut = nil
		}
	} else {
		// Legacy pipe cleanup
		if terminal.stdin != nil {
			terminal.stdin.Close()
		}
		if terminal.stdout != nil {
			terminal.stdout.Close()
		}
	}

	if terminal.cmd != nil && terminal.cmd.Process != nil {
		terminal.cmd.Process.Kill()
		terminal.cmd.Process.Wait()
		terminal.cmd.Process.Release()
	}
}

func getTerminal() string {
	var cmdTable = []string{
		`powershell.exe`,
		`cmd.exe`,
	}
	if defaultCmd != `` {
		return defaultCmd
	}
	for _, cmd := range cmdTable {
		if _, err := exec.LookPath(cmd); err == nil {
			defaultCmd = cmd
			return cmd
		}
	}
	return `cmd.exe`
}

func healthCheck() {
	const MaxInterval = 300
	for now := range time.NewTicker(30 * time.Second).C {
		timestamp := now.Unix()
		keys := make([]string, 0)
		terminals.IterCb(func(uuid string, session *terminal) bool {
			if timestamp-session.lastPack > MaxInterval {
				keys = append(keys, uuid)
				doKillTerminal(session)
			}
			return true
		})
		terminals.Remove(keys...)
	}
}
