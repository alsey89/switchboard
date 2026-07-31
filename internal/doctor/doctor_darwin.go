package doctor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/service"
)

func osChecks(cfg *config.Config, rootCertPath string) []Check {
	var checks []Check

	// /etc/resolver/<suffix> present and pointing at our DNS port.
	resolverPath := filepath.Join("/etc/resolver", cfg.Suffix)
	b, err := os.ReadFile(resolverPath)
	switch {
	case os.IsNotExist(err):
		checks = append(checks, Check{"resolver", Fail, resolverPath + " missing",
			"run: switchboard setup"})
	case err != nil:
		checks = append(checks, Check{"resolver", Warn, err.Error(), ""})
	default:
		content := string(b)
		wantPort := "port " + strconv.Itoa(cfg.EffDNSPort())
		if strings.Contains(content, "nameserver 127.0.0.1") && strings.Contains(content, wantPort) {
			checks = append(checks, Check{"resolver", OK, resolverPath + " → 127.0.0.1 " + wantPort, ""})
		} else {
			checks = append(checks, Check{"resolver", Fail,
				resolverPath + " exists but doesn't match the configured dns_port",
				"re-run: switchboard setup"})
		}
	}

	// Root CA present in the System keychain (added there by setup).
	if _, err := os.Stat(rootCertPath); err == nil {
		out, err := exec.Command("security", "find-certificate",
			"-c", "Switchboard Local CA", "/Library/Keychains/System.keychain").CombinedOutput()
		if err == nil {
			checks = append(checks, Check{"trust", OK, "root CA present in System keychain", ""})
		} else {
			detail := strings.TrimSpace(string(out))
			if detail == "" {
				detail = "root CA not found in System keychain"
			}
			checks = append(checks, Check{"trust", Fail, detail, "run: switchboard setup"})
		}
	}

	// Background service: a plist pointing at a binary that has since moved
	// (a Homebrew upgrade, a rebuild elsewhere) fails silently at boot.
	if state, plistPath, err := service.Status(); err == nil && state != service.NotInstalled {
		exe := service.InstalledExec()
		switch {
		case exe == "":
			checks = append(checks, Check{"service", Warn,
				"could not read the executable path from " + plistPath,
				"reinstall it: switchboard daemon install"})
		case !fileExists(exe):
			checks = append(checks, Check{"service", Fail,
				"launch agent points at " + exe + ", which no longer exists",
				"repoint it: switchboard daemon install"})
		case state == service.Running:
			checks = append(checks, Check{"service", OK, "launch agent running (" + exe + ")", ""})
		case state == service.Loaded:
			checks = append(checks, Check{"service", Warn, "launch agent loaded but not running (" + exe + ")",
				"check the log: switchboard daemon logs"})
		default: // service.NotLoaded
			checks = append(checks, Check{"service", Warn, "plist installed but not loaded by launchd (" + exe + ")",
				"reinstall it: switchboard daemon install"})
		}
	}

	return checks
}
