//go:build !darwin

package service

import (
	"io"
)

// Every entry point returns ErrUnsupported (declared in service.go, so
// callers can errors.Is against it on every platform) until Windows (v0.4)
// and Linux (v0.5) land; see DESIGN.md §6.

func PlistPath() (string, error) { return "", ErrUnsupported }

func Install(Spec, io.Writer) error { return ErrUnsupported }

func Uninstall(io.Writer) (removed bool, err error) { return false, ErrUnsupported }

func Status() (state State, plistPath string, err error) {
	return NotInstalled, "", ErrUnsupported
}

func InstalledExec() string { return "" }

func InstalledLogPath() string { return "" }
