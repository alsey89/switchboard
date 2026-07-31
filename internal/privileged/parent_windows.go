//go:build windows

package privileged

import (
	"os/exec"
	"syscall"
)

// Windows has no privileged-port range: an ordinary user can bind :443, so
// nothing here is ever reached. These exist so the package compiles as part
// of a cross-platform build rather than being excluded by tags at every call
// site — the seam between "bound my own socket" and "was handed one" is the
// abstraction that travels, not this mechanism.
//
// validate() rejects the run before any of this matters, because Geteuid
// returns -1 on Windows and so never equals 0.

func credential(_, _ int) *syscall.SysProcAttr { return nil }

func signalChild(cmd *exec.Cmd) {
	if cmd.Process != nil {
		cmd.Process.Kill() //nolint:errcheck
	}
}

func killChild(cmd *exec.Cmd) { signalChild(cmd) }
