package doctor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alsey89/switchboard/internal/config"
)

func osChecks(cfg *config.Config, rootCertPath string) []Check {
	var checks []Check

	// /etc/resolver/<tld> present and pointing at our DNS port.
	resolverPath := filepath.Join("/etc/resolver", cfg.TLD)
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

	return checks
}
