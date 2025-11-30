//go:build !windows

package file

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/shlex"
)

// Exec launches a file with optional arguments and working directory.
// Returns the spawned process PID.
func Exec(targetPath, args, workdir string) (int, error) {
	targetPath = strings.TrimSpace(targetPath)
	if targetPath == "" {
		return 0, errors.New(`${i18n|COMMON.INVALID_PARAMETER}`)
	}

	absPath := targetPath
	if !filepath.IsAbs(targetPath) {
		if resolved, err := filepath.Abs(targetPath); err == nil {
			absPath = resolved
		}
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return 0, err
	}
	if info.IsDir() {
		return 0, errors.New(`${i18n|EXPLORER.FILE_OR_DIR_NOT_EXIST}`)
	}
	if info.Mode()&0111 == 0 {
		return 0, errors.New(`${i18n|EXECUTE.FILE_NOT_EXECUTABLE}`)
	}

	argList, err := parseArgs(args)
	if err != nil {
		return 0, err
	}

	cmd := exec.Command(absPath, argList...)
	if workdir != "" {
		cmd.Dir = workdir
	} else if base := filepath.Dir(absPath); base != "" {
		cmd.Dir = base
	}

	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()
	return pid, nil
}

func parseArgs(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	return shlex.Split(raw)
}
