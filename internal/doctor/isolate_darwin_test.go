package doctor

import (
	"path/filepath"
	"testing"

	"github.com/alsey89/switchboard/internal/service"
	"github.com/alsey89/switchboard/internal/setup"
)

// isolateOSPaths points every absolute system path osChecks consults at a
// temporary directory.
//
// Any test that calls Run must call this. Without it the OS checks read the
// developer's own /etc/resolver and LaunchDaemons plist, so the suite reports
// on whatever that machine happens to have installed — a test asserting on
// the daemon advice would pass or fail according to state it never set up,
// and `launchctl print` would be invoked against a real job.
//
// Redirecting HOME covers the launch *agent* path, which moves with it;
// setup.ResolverDir and service.SystemPlistPath are vars for exactly this
// reason, since an absolute path does not move at all.
func isolateOSPaths(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	origResolver, origPlist := setup.ResolverDir, service.SystemPlistPath
	setup.ResolverDir = filepath.Join(dir, "etc", "resolver")
	service.SystemPlistPath = filepath.Join(dir, "LaunchDaemons", service.Label+".plist")
	t.Cleanup(func() {
		setup.ResolverDir, service.SystemPlistPath = origResolver, origPlist
	})
}
