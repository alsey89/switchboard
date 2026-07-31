//go:build windows

package daemon

import "golang.org/x/sys/windows"

var syscallEADDRINUSE error = windows.WSAEADDRINUSE
