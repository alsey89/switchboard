//go:build !darwin

package doctor

import (
	"runtime"

	"github.com/alsey89/switchboard/internal/config"
)

func osChecks(cfg *config.Config, rootCertPath string) []Check {
	return []Check{
		{"resolver", Skip, "automated resolver checks not yet available on " + runtime.GOOS,
			"see `switchboard setup` output for manual configuration"},
		{"trust", Skip, "automated trust checks not yet available on " + runtime.GOOS,
			"see `switchboard setup` output for manual configuration"},
	}
}
