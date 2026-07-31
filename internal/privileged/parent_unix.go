//go:build unix

package privileged

import (
	"os/exec"
	"syscall"
)

// credential is what makes this design work at all. Go's fork/exec on Unix
// applies Credential in the child between fork and exec, in the order
// setgroups → setgid → setuid (see runtime/syscall exec_libc2.go on darwin,
// exec_linux.go on linux). Getting that order wrong is the classic
// privilege-drop bug — setuid first and the process can no longer call
// setgid, so it keeps root's group — and the reason to let the standard
// library do it rather than hand-rolling it after start.
//
// Groups is left nil, which makes the child drop every supplementary group
// rather than keep root's. The daemon needs access only to files the target
// user owns, so its own uid and primary gid are sufficient.
//
// Setpgid puts the child in its own process group so that stopping it also
// stops anything it spawned, rather than leaving orphans holding the data
// directory.
func credential(uid, gid int) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
		Setpgid:    true,
	}
}

// signalChild asks the child's whole process group to stop. The negative pid
// is what widens it from the one process to the group Setpgid created.
func signalChild(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); err != nil {
		cmd.Process.Signal(syscall.SIGTERM) //nolint:errcheck
	}
}

func killChild(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		cmd.Process.Kill() //nolint:errcheck
	}
}
