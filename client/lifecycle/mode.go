package lifecycle

import (
	"runtime"

	"github.com/kardianos/service"
	"github.com/kataras/golog"
)

// DetectMode determines the appropriate run mode based on args and environment
func DetectMode(args []string) RunMode {
	golog.Infof("mode: Detecting run mode (args count=%d, values=%v)", len(args), args)
	// Log each argument individually for debugging
	for i, arg := range args {
		golog.Infof("mode: args[%d] = %q", i, arg)
	}

	// Check command line flags first
	if len(args) > 1 {
		golog.Infof("mode: Found %d arguments, checking arg[1]: %s", len(args), args[1])
		switch args[1] {
		case "--update", "--clean":
			golog.Info("mode: Detected RunModeUpdate")
			return RunModeUpdate
		case "--uninstall":
			golog.Info("mode: Detected RunModeUninstall")
			return RunModeUninstall
		case "--console", "--debug":
			golog.Info("mode: Detected RunModeConsole (explicit --console flag)")
			return RunModeConsole
		case "--ui-only":
			golog.Info("mode: Detected RunModeUIOnly (UI without WebSocket connection)")
			return RunModeUIOnly
		}
	} else {
		golog.Info("mode: No command line arguments provided")
	}

	// Windows-specific detection
	if runtime.GOOS == "windows" {
		interactive := service.Interactive()
		golog.Infof("mode: Windows detected, service.Interactive() = %v", interactive)

		if !interactive {
			golog.Info("mode: Detected RunModeService (running as Windows service)")
			return RunModeService
		}
		golog.Info("mode: Detected RunModeInstall (interactive session, will install service)")
		return RunModeInstall
	}

	// Non-Windows: always run as console
	golog.Info("mode: Detected RunModeConsole (non-Windows platform)")
	return RunModeConsole
}
