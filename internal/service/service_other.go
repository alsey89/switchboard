//go:build !darwin

package service

import (
	"errors"
	"io"
)

// errUnsupported is returned on platforms without service automation yet.
// Windows (v0.4) and Linux (v0.5) come later; see DESIGN.md §6.
var errUnsupported = errors.New(
	"background service installation is macOS-only so far — run `switchboard start` " +
		"under systemd, a supervisor, or your terminal in the meantime")

func PlistPath() (string, error) { return "", errUnsupported }

func Install(Spec, io.Writer) error { return errUnsupported }

func Uninstall(io.Writer) (removed bool, err error) { return false, errUnsupported }

func Status() (state State, plistPath string, err error) {
	return NotInstalled, "", errUnsupported
}

func InstalledExec() string { return "" }
