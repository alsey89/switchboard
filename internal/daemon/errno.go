//go:build unix

package daemon

import "syscall"

var syscallEADDRINUSE error = syscall.EADDRINUSE
