//go:build !darwin

package doctor

import "testing"

// isolateOSPaths is a no-op where osChecks consults no absolute system paths.
func isolateOSPaths(t *testing.T) { t.Helper() }
