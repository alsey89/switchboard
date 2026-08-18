# Dashboard Write API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the daemon's dashboard a tested HTTP API for reading diagnostics and writing config, so a browser UI can do everything the CLI does that does not need sudo.

**Architecture:** New endpoints on the existing `internal/dashboard` server. Writes go through the config file, not the running proxy, so the existing fsnotify watcher applies them exactly as it applies a hand edit. Every write carries a version hash of the file it read, and a mismatch is a 409. Mutating routes sit behind a strict origin check plus a CSRF token, both enforced by a table walk so a new route cannot forget them.

**Tech Stack:** Go 1.25, stdlib `net/http` with `ServeMux`, `BurntSushi/toml` via the existing `internal/config`. No new modules.

**Spec:** `docs/superpowers/specs/2026-08-18-dashboard-write-surface-design.md`

**Scope note:** This is plan 1 of 2. It builds the Go API only. The SPA that consumes it (Vite, React, Tailwind, shadcn/ui, the inspector port, deleting `console.html`) is plan 2, written after this lands. The existing console keeps working untouched throughout this plan.

## Global Constraints

- **No new Go modules.** The repo has a standing no-new-modules constraint (DESIGN.md decision 10). Everything here is stdlib.
- **Go 1.25.1.** `go.mod` line 3.
- **Prose style for every comment and doc:** short sentences, no em dashes, little jargon. Match the surrounding files, which explain *why* and not *what*.
- **The listener stays on 127.0.0.1.** Nothing in this plan binds anything else.
- **Never `innerHTML`.** Not relevant to Go, but `console.html` is touched in Task 5 and the rule holds.
- **Commits use Conventional Commits.** `feat:`, `fix:`, `docs:`, `test:`, `refactor:`. Body explains why. No AI attribution.
- **Branch:** `feat/dashboard-gui`. Already created, already carries the spec commit.
- **Every task ends green.** `go build ./... && go vet ./... && go test ./...` passes before every commit.

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/config/config.go` | Gains `Version` and `LoadWithVersion`. `Load` becomes a thin wrapper so the two cannot drift. |
| `internal/dashboard/dashboard.go` | Server wiring. `routeEntry` gains `method` and `mutating`. `SetPaths`, `SetApplied`, bound port recording. |
| `internal/dashboard/origin.go` | New. `sameOriginStrict`, the CSRF token, the `mutate` wrapper. All the security surface in one file so a reviewer can read it in one sitting. |
| `internal/dashboard/status.go` | New. `GET /api/doctor` and `GET /api/service`. Read-only diagnostics. |
| `internal/dashboard/configapi.go` | New. `GET /api/config`, `PATCH /api/config`, the shared `withConfig` write helper and the version guard. |
| `internal/dashboard/routesapi.go` | New. `POST`, `PATCH` and `DELETE` on routes. |
| `internal/daemon/daemon.go` | Passes paths to the dashboard. Reports each reload outcome. |
| `docs/adr/0004-the-dashboard-write-surface.md` | New. The threat model and why there is no auth. |
| `DESIGN.md` | New decision row for the write surface. |

Writes are split across `configapi.go` and `routesapi.go` rather than one `write.go`, because routes are a list with their own identity rules and settings are scalar fields. They change for different reasons.

---

### Task 1: Config version hash

The primitive every write depends on. Standalone and reviewable on its own.

**Files:**
- Modify: `internal/config/config.go:147-188`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `config.Version(b []byte) string`, `config.LoadWithVersion(path string) (*Config, string, error)`. `Load(path string) (*Config, error)` keeps its exact current signature and behavior.

- [ ] **Step 1: Write the failing tests**

Append to `internal/config/config_test.go`:

```go
func TestVersionChangesWithContent(t *testing.T) {
	a := Version([]byte("suffix = \"test\"\n"))
	b := Version([]byte("suffix = \"test\"\n\n"))
	if a == b {
		t.Fatal("different bytes produced the same version")
	}
	if a != Version([]byte("suffix = \"test\"\n")) {
		t.Fatal("the same bytes produced different versions")
	}
	if len(a) != 16 {
		t.Fatalf("version is %d chars, want 16", len(a))
	}
}

func TestLoadWithVersionMatchesLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := "suffix = \"test\"\n\n[[routes]]\ndomain = \"app.test\"\nport = 3000\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, version, err := LoadWithVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	if version != Version([]byte(body)) {
		t.Fatalf("version %q does not match the file bytes", version)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].Domain != "app.test" {
		t.Fatalf("config did not load: %+v", cfg)
	}

	// Load must stay exactly equivalent. It is called from the daemon, the
	// CLI and doctor, and this refactor must not change any of them.
	plain, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(plain.Routes) != len(cfg.Routes) || plain.Suffix != cfg.Suffix {
		t.Fatalf("Load and LoadWithVersion disagree: %+v vs %+v", plain, cfg)
	}
}

// A missing file is not an error. It yields defaults and an empty version,
// so a first write from a fresh install sends "" and matches.
func TestLoadWithVersionMissingFile(t *testing.T) {
	cfg, version, err := LoadWithVersion(filepath.Join(t.TempDir(), "nope.toml"))
	if err != nil {
		t.Fatalf("a missing file should not error: %v", err)
	}
	if version != "" {
		t.Fatalf("version %q, want empty for a missing file", version)
	}
	if cfg.Suffix != DefaultSuffix {
		t.Fatalf("suffix %q, want the default", cfg.Suffix)
	}
}

func TestLoadWithVersionRejectsBrokenToml(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("this is not toml {{{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadWithVersion(path); err == nil {
		t.Fatal("expected a parse error")
	}
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `go test ./internal/config/ -run 'Version' -v`
Expected: FAIL, `undefined: Version` and `undefined: LoadWithVersion`.

- [ ] **Step 3: Implement**

Add to the import block in `internal/config/config.go`: `"crypto/sha256"` and `"encoding/hex"`.

Replace the body of `Load` (lines 167-188) and add the two new functions:

```go
// Version identifies the exact bytes of a config file. A write request
// echoes back the version it read, so an edit made against a stale view
// fails loudly instead of quietly clobbering someone else's change.
//
// Sixteen hex characters, not the full digest. This is a collision check
// between two edits seconds apart, not a security boundary, and a short
// value is one a human can compare in a log line.
func Version(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:16]
}

// LoadWithVersion is Load plus the version of the bytes it read.
//
// Anything that intends to write the file back must use this rather than
// Load followed by a separate read. The hash has to come from the same read
// as the config, or the guard is racing the thing it exists to prevent.
//
// A missing file yields defaults and an empty version, matching Load's rule
// that the tool works before `add` has ever run.
func LoadWithVersion(path string) (*Config, string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), "", nil
	}
	if err != nil {
		return nil, "", err
	}
	c, err := decode(b, path)
	if err != nil {
		return nil, "", err
	}
	return c, Version(b), nil
}

// Load reads and validates the config at path. A missing file yields the
// default config (not an error): the tool should work before `add` runs.
func Load(path string) (*Config, error) {
	c, _, err := LoadWithVersion(path)
	return c, err
}

// decode parses and validates config bytes. Split out so Load and
// LoadWithVersion share one implementation and cannot drift.
func decode(b []byte, path string) (*Config, error) {
	var c Config
	if _, err := toml.Decode(string(b), &c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if c.Suffix == "" {
		c.Suffix = DefaultSuffix
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}
```

- [ ] **Step 4: Run the whole config suite**

Run: `go test ./internal/config/ -v`
Expected: PASS. Every pre-existing `Load` test must still pass. If any fails, the refactor changed behavior and the refactor is wrong, not the test.

- [ ] **Step 5: Run everything**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: add a version hash to config loading

A write API needs to detect that the file changed between the read a client
rendered from and the write it sends back. LoadWithVersion returns the hash
of the same bytes it parsed, so the guard cannot race the read it guards.

Load keeps its signature and becomes a wrapper, so the daemon, the CLI and
doctor are untouched."
```

---

### Task 2: Path injection and GET /api/doctor

**Files:**
- Modify: `internal/dashboard/dashboard.go`
- Create: `internal/dashboard/status.go`
- Modify: `internal/daemon/daemon.go:126`
- Test: `internal/dashboard/status_test.go`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `(*Server).SetPaths(configPath, dataDir string)`, `(*Server).pathsOr503(w http.ResponseWriter) (*paths, bool)`, and the `routeEntry` struct with keyed fields.

**Design note, a deliberate deviation from the spec.** The spec said `New` grows an options struct. Use a `SetPaths` setter instead. `New(cfg, version)` is called in a dozen existing tests that have no filesystem, and the Server already uses setter injection for exactly this shape (`SetConfig`, `SetInspector`). A handler that needs paths and has none answers 503, which mirrors `recorder()` answering 503 when capture is off. Zero test churn and one fewer idiom in the file.

- [ ] **Step 1: Convert `routeEntry` to keyed fields and add `method`**

In `internal/dashboard/dashboard.go`, replace the `routeEntry` type and `routes()` and `mux()`:

```go
// routeEntry pairs a mux pattern with its handler and the protections the
// handler is claiming. mux() registers this table, and the guard tests walk
// the same table, so a route that forgets a protection fails those tests by
// construction. That is exactly how /api/routes escaped the guard in the
// first place: it lived only in mux()'s hand-written list, and the
// equivalent hand-written test list never had a reason to know it existed.
type routeEntry struct {
	// method is the HTTP method this entry serves. Empty means any method.
	// Kept separate from pattern rather than folded into it as Go 1.22's
	// "POST /path" syntax, because the guard tests need to build a request
	// from these fields and splitting a string back apart to do it is a
	// parser nobody should have to maintain.
	method   string
	pattern  string
	handler  http.HandlerFunc
	guarded  bool
	mutating bool
}

func (s *Server) routes() []routeEntry {
	return []routeEntry{
		{pattern: "/api/routes", handler: s.guard(s.handleAPIRoutes), guarded: true},
		{pattern: "/api/doctor", handler: s.guard(s.handleDoctor), guarded: true},
		{pattern: "/api/inspect/requests", handler: s.guard(s.handleInspectRequests), guarded: true},
		{pattern: "/api/inspect/requests/", handler: s.guard(s.handleInspectRecord), guarded: true},
		{pattern: "/api/inspect/clear", handler: s.guard(s.handleInspectClear), guarded: true},
		{pattern: "/api/inspect/stream", handler: s.guard(s.handleInspectStream), guarded: true},
		{pattern: "/inspect", handler: s.guardPage(s.handleInspectRedirect), guarded: true},
		// handleRoot is its own guard: it needs the "/" vs any-other-path
		// split alongside the host check, and it answers a foreign Host
		// with the no-route page rather than delegating to guardPage.
		{pattern: "/", handler: s.handleRoot},
	}
}

func (s *Server) mux() *http.ServeMux {
	mux := http.NewServeMux()
	for _, rt := range s.routes() {
		pattern := rt.pattern
		if rt.method != "" {
			pattern = rt.method + " " + pattern
		}
		mux.HandleFunc(pattern, rt.handler)
	}
	return mux
}
```

- [ ] **Step 2: Add the paths field and setter**

Add to the `Server` struct in `internal/dashboard/dashboard.go`, next to `insp`:

```go
	// paths are the filesystem locations the diagnostic and write endpoints
	// need. Injected after New rather than passed to it, matching
	// SetInspector: New is called in tests that have no filesystem, and a
	// handler with no paths answers 503 exactly as an inspector handler does
	// when capture is off.
	paths atomic.Pointer[paths]
```

And below `SetInspector`:

```go
// paths is what SetPaths stores. A single pointer so the two values are
// always swapped together and a handler can never read one from before a
// reload and one from after.
type paths struct{ configPath, dataDir string }

// SetPaths tells the dashboard where the config file and data directory
// live. Without them the diagnostic and write endpoints answer 503.
func (s *Server) SetPaths(configPath, dataDir string) {
	s.paths.Store(&paths{configPath: configPath, dataDir: dataDir})
}

// pathsOr503 is the paths counterpart to recorder(): it answers the request
// itself when the dependency is absent, so callers stay a two-line guard.
func (s *Server) pathsOr503(w http.ResponseWriter) (*paths, bool) {
	p := s.paths.Load()
	if p == nil {
		http.Error(w, "this daemon was started without filesystem paths",
			http.StatusServiceUnavailable)
		return nil, false
	}
	return p, true
}
```

- [ ] **Step 3: Write the failing test**

Create `internal/dashboard/status_test.go`:

```go
package dashboard

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/alsey89/switchboard/internal/config"
)

// serverWithPaths is a dashboard wired to a real config file on disk. The
// write and diagnostic endpoints all read from disk rather than from s.cfg,
// so a test that only sets s.cfg proves nothing about them.
func serverWithPaths(t *testing.T, body string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	s := New(&config.Config{Suffix: "test"}, "test")
	s.SetPaths(path, dir)
	return s, path
}

func TestDoctorReturnsChecks(t *testing.T) {
	s, _ := serverWithPaths(t, "suffix = \"test\"\n")

	w := do(s, "GET", "/api/doctor", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}

	var checks []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &checks); err != nil {
		t.Fatal(err)
	}
	if len(checks) == 0 {
		t.Fatal("doctor returned no checks")
	}
	// Status must be the string, not the int. The SPA should not have to
	// carry a second copy of the Status-to-name mapping.
	for _, c := range checks {
		switch c.Status {
		case "ok", "warn", "FAIL", "skip":
		default:
			t.Errorf("check %q has status %q, want a doctor.Status string", c.Name, c.Status)
		}
	}
}

// Doctor's whole job includes reporting a config that will not parse, so it
// reads the file rather than s.cfg, which by construction only ever holds a
// config that parsed.
func TestDoctorReportsABrokenConfig(t *testing.T) {
	s, _ := serverWithPaths(t, "this is not toml {{{")

	w := do(s, "GET", "/api/doctor", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (a broken config is a finding, not an error)", w.Code)
	}
	if !jsonHasFailingCheck(t, w.Body.Bytes(), "config") {
		t.Errorf("expected a failing config check, got: %s", w.Body)
	}
}

func jsonHasFailingCheck(t *testing.T, body []byte, name string) bool {
	t.Helper()
	var checks []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &checks); err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		if c.Name == name && c.Status == "FAIL" {
			return true
		}
	}
	return false
}

func TestDoctorIs503WithoutPaths(t *testing.T) {
	s := New(&config.Config{Suffix: "test"}, "test")
	if w := do(s, "GET", "/api/doctor", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", w.Code)
	}
}
```

- [ ] **Step 4: Run it and watch it fail**

Run: `go test ./internal/dashboard/ -run Doctor -v`
Expected: FAIL, `s.handleDoctor undefined`.

- [ ] **Step 5: Implement the handler**

Create `internal/dashboard/status.go`:

```go
// Read-only diagnostic endpoints. Everything here reads the filesystem or
// launchd rather than s.cfg, because their whole purpose is reporting the
// state the daemon is running in, including the parts that are broken.
package dashboard

import (
	"net/http"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/doctor"
)

// checkView is one doctor.Check on the wire. Status goes out as its string,
// not its int: doctor.Status already has a String method, and an int would
// make every consumer keep a second copy of the mapping.
type checkView struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	Hint   string `json:"hint,omitempty"`
}

func (s *Server) handleDoctor(w http.ResponseWriter, r *http.Request) {
	p, ok := s.pathsOr503(w)
	if !ok {
		return
	}
	// Read from disk, not from s.cfg. Reporting a config that fails to parse
	// is one of doctor's jobs, and s.cfg only ever holds one that parsed.
	// doctor.Run substitutes defaults itself when cfgErr is non-nil.
	cfg, cfgErr := config.Load(p.configPath)
	checks := doctor.Run(cfg, p.configPath, p.dataDir, cfgErr)

	out := make([]checkView, 0, len(checks))
	for _, c := range checks {
		out = append(out, checkView{
			Name:   c.Name,
			Status: c.Status.String(),
			Detail: c.Detail,
			Hint:   c.Hint,
		})
	}
	writeJSON(w, out)
}
```

- [ ] **Step 6: Run the test**

Run: `go test ./internal/dashboard/ -run Doctor -v`
Expected: PASS, all three.

- [ ] **Step 7: Wire the daemon**

In `internal/daemon/daemon.go`, immediately after line 126 (`dash := dashboard.New(cfg, opts.Version)`):

```go
	dash.SetPaths(opts.ConfigPath, opts.DataDir)
```

- [ ] **Step 8: Run everything**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: PASS. `TestEveryGuardedRouteRejectsAForeignHost` now covers `/api/doctor` for free, because it walks `routes()`.

- [ ] **Step 9: Commit**

```bash
git add internal/dashboard/dashboard.go internal/dashboard/status.go \
        internal/dashboard/status_test.go internal/daemon/daemon.go
git commit -m "feat: serve doctor output from the dashboard

doctor.Run is already a pure function over a config, a path and a data dir.
The dashboard just did not know two of the three, so SetPaths tells it, the
same way SetInspector already tells it about capture.

The endpoint reads the config from disk rather than from s.cfg. Reporting a
config that will not parse is half of what doctor is for, and s.cfg only
ever holds one that parsed."
```

---

### Task 3: GET /api/service

**Files:**
- Modify: `internal/dashboard/status.go`
- Modify: `internal/dashboard/dashboard.go` (one `routes()` entry)
- Test: `internal/dashboard/status_test.go`

**Interfaces:**
- Consumes: `pathsOr503` from Task 2. Not actually needed here, but the entry sits beside it.
- Produces: `GET /api/service` returning `{"state": string, "plistPath": string, "supported": bool}`.

- [ ] **Step 1: Write the failing test**

Append to `internal/dashboard/status_test.go`:

```go
// service.Status shells out to launchctl and is macOS-only. On every other
// platform it returns an error alongside NotInstalled, and callers must
// check the error first. The endpoint must report that as "unsupported"
// rather than as a 500, because a Linux user is not experiencing a failure.
func TestServiceEndpointAlwaysAnswers(t *testing.T) {
	s, _ := serverWithPaths(t, "suffix = \"test\"\n")

	w := do(s, "GET", "/api/service", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}

	var out struct {
		State     string `json:"state"`
		PlistPath string `json:"plistPath"`
		Supported bool   `json:"supported"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.State == "" {
		t.Error("state should always be populated, even when unsupported")
	}
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `go test ./internal/dashboard/ -run Service -v`
Expected: FAIL, 404 because the route does not exist.

- [ ] **Step 3: Implement**

Append to `internal/dashboard/status.go` (and add `"github.com/alsey89/switchboard/internal/service"` to the imports):

```go
// serviceView is what the dashboard knows about the background service.
//
// Supported exists because service.Status is macOS-only. Everywhere else it
// returns an error next to NotInstalled, and that is not a failure the user
// caused or can act on. A Linux user should see "not supported here", not a
// red 500.
type serviceView struct {
	State     string `json:"state"`
	PlistPath string `json:"plistPath,omitempty"`
	Supported bool   `json:"supported"`
}

func (s *Server) handleService(w http.ResponseWriter, r *http.Request) {
	state, plistPath, err := service.Status()
	if err != nil {
		writeJSON(w, serviceView{State: "not supported on this platform"})
		return
	}
	writeJSON(w, serviceView{
		State:     state.String(),
		PlistPath: plistPath,
		Supported: true,
	})
}
```

Add to `routes()` in `dashboard.go`, directly after the `/api/doctor` entry:

```go
		{pattern: "/api/service", handler: s.guard(s.handleService), guarded: true},
```

- [ ] **Step 4: Run the test**

Run: `go test ./internal/dashboard/ -run Service -v`
Expected: PASS.

- [ ] **Step 5: Run everything**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/dashboard/status.go internal/dashboard/status_test.go internal/dashboard/dashboard.go
git commit -m "feat: report background service state from the dashboard

Doctor says whether the daemon is reachable. This says whether launchd knows
about it, which is the difference between 'start it' and 'install it'.

Reports unsupported rather than erroring on platforms where service.Status
is not implemented. A Linux user has not hit a failure."
```

---

### Task 4: GET /api/config

**Files:**
- Create: `internal/dashboard/configapi.go`
- Modify: `internal/dashboard/dashboard.go` (one `routes()` entry)
- Test: `internal/dashboard/configapi_test.go`

**Interfaces:**
- Consumes: `config.LoadWithVersion` (Task 1), `pathsOr503` (Task 2).
- Produces: `configView` struct and `(*Server).writeConfigView(w http.ResponseWriter) bool`. Task 6 and Task 8 both reuse `writeConfigView` to answer a successful write, and Task 9 adds `applied` and `restartRequired` to `configView`.

- [ ] **Step 1: Write the failing test**

Create `internal/dashboard/configapi_test.go`:

```go
package dashboard

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/alsey89/switchboard/internal/config"
)

// readConfigView is how every config test in this file inspects a response.
// The shape is asserted once here so a field rename shows up as one
// compile error rather than as six silently-zero values.
type readConfigView struct {
	Version string `json:"version"`
	Suffix  string `json:"suffix"`
	Routes  []struct {
		Domain   string `json:"domain"`
		Upstream string `json:"upstream"`
	} `json:"routes"`
	Effective struct {
		HTTPPort      int `json:"httpPort"`
		HTTPSPort     int `json:"httpsPort"`
		DNSPort       int `json:"dnsPort"`
		DashboardPort int `json:"dashboardPort"`
	} `json:"effective"`
	Inspect struct {
		Enabled bool `json:"enabled"`
		Bodies  bool `json:"bodies"`
	} `json:"inspect"`
}

func getConfig(t *testing.T, s *Server) readConfigView {
	t.Helper()
	w := do(s, "GET", "/api/config", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}
	var out readConfigView
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestConfigEndpointReportsFileAndEffectiveValues(t *testing.T) {
	body := "suffix = \"test\"\n\n[[routes]]\ndomain = \"app.test\"\nport = 3000\n"
	s, _ := serverWithPaths(t, body)

	out := getConfig(t, s)

	if out.Version != config.Version([]byte(body)) {
		t.Errorf("version %q does not match the file", out.Version)
	}
	if out.Suffix != "test" {
		t.Errorf("suffix %q, want test", out.Suffix)
	}
	if len(out.Routes) != 1 || out.Routes[0].Domain != "app.test" {
		t.Fatalf("routes: %+v", out.Routes)
	}
	if out.Routes[0].Upstream != "127.0.0.1:3000" {
		t.Errorf("upstream %q, want the resolved address", out.Routes[0].Upstream)
	}
	// Effective values are what the daemon actually uses. The file sets no
	// ports, so every one of these must be a default and not a zero.
	if out.Effective.HTTPSPort != config.DefaultHTTPSPort {
		t.Errorf("https port %d, want %d", out.Effective.HTTPSPort, config.DefaultHTTPSPort)
	}
	if out.Effective.DashboardPort != config.DefaultDashboardPort {
		t.Errorf("dashboard port %d, want %d", out.Effective.DashboardPort, config.DefaultDashboardPort)
	}
	// Inspect defaults to on. A plain bool cannot tell unset from off, which
	// is why config uses a pointer, and the endpoint must resolve it.
	if !out.Inspect.Enabled {
		t.Error("inspect should default to enabled")
	}
}

func TestConfigEndpointIs503WithoutPaths(t *testing.T) {
	s := New(&config.Config{Suffix: "test"}, "test")
	if w := do(s, "GET", "/api/config", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", w.Code)
	}
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `go test ./internal/dashboard/ -run ConfigEndpoint -v`
Expected: FAIL, 404.

- [ ] **Step 3: Implement**

Create `internal/dashboard/configapi.go`:

```go
// The config endpoints. Reading is a straight projection of the file plus
// the effective values the accessors resolve. Writing lives here too,
// because the version guard and the read projection have to agree about
// what a config looks like on the wire.
package dashboard

import (
	"encoding/json"
	"net/http"

	"github.com/alsey89/switchboard/internal/config"
)

// configView is the config on the wire.
//
// It carries both what the file says and what the daemon actually uses.
// Those differ for every unset port, and a settings form needs both: the
// effective value to display, and the file value to know whether the field
// is explicitly set or inherited.
type configView struct {
	Version   string         `json:"version"`
	Suffix    string         `json:"suffix"`
	Routes    []routeView    `json:"routes"`
	Effective effectiveView  `json:"effective"`
	Ports     portsView      `json:"ports"`
	Inspect   inspectView    `json:"inspect"`
}

// effectiveView is what the daemon runs with, defaults resolved.
type effectiveView struct {
	HTTPPort      int `json:"httpPort"`
	HTTPSPort     int `json:"httpsPort"`
	DNSPort       int `json:"dnsPort"`
	DashboardPort int `json:"dashboardPort"`
}

// portsView is what the file literally says. Zero means unset, which is a
// different fact from "set to the default" and the one a form needs.
type portsView struct {
	HTTPPort      int `json:"httpPort"`
	HTTPSPort     int `json:"httpsPort"`
	DNSPort       int `json:"dnsPort"`
	DashboardPort int `json:"dashboardPort"`
}

// inspectView resolves the inspect settings through the accessors. Never
// read the struct directly: the zero value of every field means default,
// and Enabled defaults to true.
type inspectView struct {
	Enabled      bool   `json:"enabled"`
	Bodies       bool   `json:"bodies"`
	MaxRequests  int    `json:"maxRequests"`
	MaxBytes     int64  `json:"maxBytes"`
	MaxBodyBytes int    `json:"maxBodyBytes"`
	MaxAge       string `json:"maxAge"`
}

func (s *Server) newConfigView(cfg *config.Config, version string) configView {
	return configView{
		Version: version,
		Suffix:  cfg.Suffix,
		Routes:  s.routeViews(cfg),
		Effective: effectiveView{
			HTTPPort:      cfg.EffHTTPPort(),
			HTTPSPort:     cfg.EffHTTPSPort(),
			DNSPort:       cfg.EffDNSPort(),
			DashboardPort: cfg.EffDashboardPort(),
		},
		Ports: portsView{
			HTTPPort:      cfg.HTTPPort,
			HTTPSPort:     cfg.HTTPSPort,
			DNSPort:       cfg.DNSPort,
			DashboardPort: cfg.DashboardPort,
		},
		Inspect: inspectView{
			Enabled:      cfg.InspectEnabled(),
			Bodies:       cfg.InspectBodies(),
			MaxRequests:  cfg.InspectMaxRequests(),
			MaxBytes:     cfg.InspectMaxBytes(),
			MaxBodyBytes: cfg.InspectMaxBodyBytes(),
			MaxAge:       cfg.InspectMaxAge().String(),
		},
	}
}

// writeConfigView answers with the config as it now stands on disk. Both
// the read endpoint and every successful write end here, so a client never
// has to follow a write with a read to find out what happened.
//
// status is a parameter rather than always 200 because a create answers 201.
// It cannot be left to the caller to WriteHeader first: Content-Type has to
// be set before the status is written, and a caller that got that order
// wrong would send a correct body with no content type and nothing would
// fail loudly.
func (s *Server) writeConfigView(w http.ResponseWriter, status int) bool {
	p, ok := s.pathsOr503(w)
	if !ok {
		return false
	}
	cfg, version, err := config.LoadWithVersion(p.configPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(s.newConfigView(cfg, version)) //nolint:errcheck
	return true
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	s.writeConfigView(w, http.StatusOK)
}
```

Add to `routes()` in `dashboard.go`, after the `/api/service` entry:

```go
		{pattern: "/api/config", handler: s.guard(s.handleConfig), guarded: true},
```

- [ ] **Step 4: Confirm the accessor names**

Run: `go doc ./internal/config Config | grep Inspect`
Expected: the five `Inspect*` accessors used above exist with those exact names. If `InspectMaxAge` returns a `time.Duration`, `.String()` is correct. If any name differs, fix the call, not the test.

- [ ] **Step 5: Run the test**

Run: `go test ./internal/dashboard/ -run ConfigEndpoint -v`
Expected: PASS.

- [ ] **Step 6: Run everything**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/dashboard/configapi.go internal/dashboard/configapi_test.go internal/dashboard/dashboard.go
git commit -m "feat: serve the config from the dashboard

Sends both what the file says and what the daemon actually runs with. A
settings form needs both: the effective value to show, and the file value to
know whether a field is set or inherited. Those differ for every unset port.

Inspect settings go through the accessors, because the zero value of every
one of them means default and Enabled defaults to true."
```

---

### Task 5: The origin model

The security surface. Land it before any write endpoint exists, and prove it against `handleInspectClear`, which already mutates.

**Files:**
- Create: `internal/dashboard/origin.go`
- Modify: `internal/dashboard/dashboard.go` (Server field, `routes()`)
- Modify: `internal/dashboard/inspect.go:171-189` (`handleInspectClear`)
- Modify: `internal/dashboard/templates/console.html`
- Create: `docs/adr/0004-the-dashboard-write-surface.md`
- Modify: `DESIGN.md`
- Test: `internal/dashboard/origin_test.go`

**Interfaces:**
- Consumes: `routeEntry.mutating` (Task 2).
- Produces: `(*Server).mutate(h http.HandlerFunc) http.HandlerFunc` and the exported-for-tests field `Server.csrf string`. Tasks 6 and 8 wrap every write handler in `s.guard(s.mutate(...))` and set `mutating: true`.

- [ ] **Step 1: Write the failing tests**

Create `internal/dashboard/origin_test.go`:

```go
package dashboard

import (
	"net/http"
	"strings"
	"testing"
)

// badWriteHeaders is every way a request can fail the write checks. Each
// case is a real attack shape, not a permutation for its own sake:
//
//   - no origin: a form post, which browsers send with no Origin at all
//   - foreign origin: an ordinary hostile page
//   - loopback on another port: your own dev server, one bad npm dependency
//     deep. This is the case sameOrigin lets through and the reason
//     sameOriginStrict exists.
//   - right origin, no or wrong token: defence in depth behind the above
func badWriteHeaders(goodToken string) []struct {
	name string
	hdr  map[string]string
} {
	return []struct {
		name string
		hdr  map[string]string
	}{
		{"no origin", map[string]string{"X-Switchboard-CSRF": goodToken}},
		{"foreign origin", map[string]string{
			"Origin": "https://evil.example", "X-Switchboard-CSRF": goodToken}},
		{"loopback on another port", map[string]string{
			"Origin": "http://127.0.0.1:3000", "X-Switchboard-CSRF": goodToken}},
		{"loopback with no port", map[string]string{
			"Origin": "http://127.0.0.1", "X-Switchboard-CSRF": goodToken}},
		{"right origin, no token", map[string]string{
			"Origin": "https://switchboard.test"}},
		{"right origin, wrong token", map[string]string{
			"Origin": "https://switchboard.test", "X-Switchboard-CSRF": "not-the-token"}},
	}
}

// TestEveryMutatingRouteRejectsABadWrite walks s.routes() the same way
// TestEveryGuardedRouteRejectsAForeignHost does, for the same reason: a
// write endpoint added without the mutate wrapper fails this by
// construction rather than by someone remembering to add a case.
func TestEveryMutatingRouteRejectsABadWrite(t *testing.T) {
	s, _ := testServer(t)

	var found int
	for _, rt := range s.routes() {
		if !rt.mutating {
			continue
		}
		found++
		target := rt.pattern
		if strings.HasSuffix(target, "/") {
			target += "app.test"
		}
		method := rt.method
		if method == "" {
			method = "POST"
		}
		for _, c := range badWriteHeaders(s.csrf) {
			t.Run(rt.pattern+" "+c.name, func(t *testing.T) {
				w := do(s, method, target, c.hdr)
				if w.Code != http.StatusForbidden {
					t.Fatalf("status %d, want 403", w.Code)
				}
			})
		}
	}
	// A vacuous pass is the failure mode this whole test exists to avoid.
	if found == 0 {
		t.Fatal("no mutating routes found; this test proved nothing")
	}
}

func TestGoodOriginAndTokenReachTheHandler(t *testing.T) {
	s, _ := testServer(t)
	hdr := map[string]string{
		"Origin":             "https://switchboard.test",
		"X-Switchboard-CSRF": s.csrf,
	}
	// handleInspectClear with a live recorder answers 204.
	if w := do(s, "POST", "/api/inspect/clear", hdr); w.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204: %s", w.Code, w.Body)
	}
}

// Loopback at the dashboard port is the break-glass path and must keep
// working for writes as well as reads. When the resolver file or the CA
// trust is broken, this is the only way to reach the dashboard at all.
func TestLoopbackAtTheDashboardPortIsAllowed(t *testing.T) {
	s, _ := testServer(t)
	hdr := map[string]string{
		"Origin":             "http://127.0.0.1:8484",
		"X-Switchboard-CSRF": s.csrf,
	}
	if w := do(s, "POST", "/api/inspect/clear", hdr); w.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204: %s", w.Code, w.Body)
	}
}

func TestTokenIsPerProcessAndNotEmpty(t *testing.T) {
	a, _ := testServer(t)
	b, _ := testServer(t)
	if a.csrf == "" {
		t.Fatal("token is empty")
	}
	if len(a.csrf) != 64 {
		t.Fatalf("token is %d chars, want 64 hex chars for 32 bytes", len(a.csrf))
	}
	if a.csrf == b.csrf {
		t.Fatal("two servers minted the same token")
	}
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `go test ./internal/dashboard/ -run 'Mutating|GoodOrigin|Loopback|Token' -v`
Expected: FAIL, `s.csrf undefined`.

- [ ] **Step 3: Implement**

Create `internal/dashboard/origin.go`:

```go
// Everything that decides whether a state-changing request is allowed.
//
// Kept in one file on purpose. The reasoning is subtle, the failure is
// silent, and a reviewer should be able to read the whole boundary without
// jumping between files. See docs/adr/0004 for the threat model.
package dashboard

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// csrfHeader is where the page sends the token back.
const csrfHeader = "X-Switchboard-CSRF"

// newCSRFToken mints the per-process token.
//
// A foreign page cannot learn it. Reading the dashboard page cross-origin
// requires CORS, and this server grants none, so an attacker's page can fire
// a request it is unable to read the response to. The token is defence in
// depth behind sameOriginStrict, which is the real gate.
//
// Panics rather than degrading. A crypto/rand failure means the OS entropy
// source is gone, and quietly serving a predictable token would be worse
// than not starting.
func newCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("switchboard: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// sameOriginStrict is the origin check every write must pass.
//
// It is deliberately narrower than the host guard. hostAllowed accepts any
// loopback address, and that is right for reads: when the resolver file or
// the CA trust is broken, http://127.0.0.1:8484 is the only way in, and that
// is exactly the moment you need doctor. Loosening reads is the entire point
// of that allowance.
//
// It is wrong for writes. Every dev server this proxy sits in front of is on
// loopback too, so one bad npm dependency inside your own app would be
// inside the trust boundary and could repoint a route at a server it
// controls. sameOrigin's own comment predicted this and asked for it to be
// revisited before a bigger blast radius arrived. This is that.
//
// Writes therefore require the dashboard's own domain, or loopback at the
// dashboard port specifically. Loopback with no explicit port is not the
// dashboard, since the dashboard never runs on 80 or 443.
func (s *Server) sameOriginStrict(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return false
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	cfg := s.cfg.Load()
	host := strings.ToLower(hostOnly(u.Host))
	if host == cfg.DashboardDomain() {
		return true
	}
	if !isLoopbackHost(host) {
		return false
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return false
	}
	return port == strconv.Itoa(cfg.EffDashboardPort())
}

// mutate wraps a state-changing handler in the two checks a write needs on
// top of guard. Every entry in routes() marked mutating goes through this,
// and TestEveryMutatingRouteRejectsABadWrite walks the same table to prove
// it, so a new write endpoint cannot quietly skip it.
//
// guard still has to be applied as well. A Host check is necessary for a
// mutating route and was never sufficient on its own, because a Host header
// is something an attacker's page gets to send too.
func (s *Server) mutate(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.sameOriginStrict(r) {
			http.Error(w, "bad origin", http.StatusForbidden)
			return
		}
		sent := []byte(r.Header.Get(csrfHeader))
		if subtle.ConstantTimeCompare(sent, []byte(s.csrf)) != 1 {
			http.Error(w, "bad csrf token", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}
```

- [ ] **Step 4: Add the field and mint the token in `New`**

In `internal/dashboard/dashboard.go`, add to the `Server` struct:

```go
	// csrf is minted once per process and injected into the page. See
	// origin.go.
	csrf string
```

And in `New`, in the same literal that sets `version`:

```go
	s := &Server{
		version: version,
		csrf:    newCSRFToken(),
		done:    make(chan struct{}),
		probes:  newProber(probeTTL),
	}
```

- [ ] **Step 5: Move `handleInspectClear` behind `mutate`**

In `routes()`, change the clear entry to:

```go
		{pattern: "/api/inspect/clear", handler: s.guard(s.mutate(s.handleInspectClear)),
			guarded: true, mutating: true},
```

Then in `internal/dashboard/inspect.go`:

- Delete the `sameOrigin` check from `handleInspectClear` (lines 176-179), leaving the method check in place. Update the function's comment to point at `mutate`.
- **Delete `sameOrigin` itself** (lines 191-216). `handleInspectClear` was its only caller, so leaving it would be dead code. Its long comment about loopback trust is not lost: the reasoning moves into `sameOriginStrict`, which is where it now applies.

Because `sameOrigin` is going away, `sameOriginStrict`'s doc comment cannot document itself by contrast with a function that no longer exists. Write it against `hostAllowed`, which keeps the permissive loopback rule for reads via `isLoopbackHost`. Adjust the first paragraph of the comment shown above to read:

```go
// sameOriginStrict is the origin check every write must pass.
//
// It is deliberately narrower than the host guard. hostAllowed accepts any
// loopback address, and that is right for reads: when the resolver file or
// the CA trust is broken, http://127.0.0.1:8484 is the only way in, and
// that is exactly the moment you need doctor. Loosening reads is the entire
// point of that allowance.
```

Keep the remaining paragraphs as written.

- [ ] **Step 6: Inject the token into the page**

In `handleRoot` in `dashboard.go`, add `CSRF string` to the anonymous struct and set it to `s.csrf`. In `internal/dashboard/templates/console.html`, add inside `<head>`:

```html
<meta name="switchboard-csrf" content="{{.CSRF}}">
```

The current console does not write anything, so it does not read this yet. It goes in now so the token is exercised by a real page render, and so plan 2's `index.html` inherits a mechanism that already works.

- [ ] **Step 7: Run the tests**

Run: `go test ./internal/dashboard/ -v`
Expected: PASS, including the existing clear tests. Any existing test that posts to `/api/inspect/clear` with only an `Origin` header now needs the token too. Update those tests, do not weaken `mutate`.

- [ ] **Step 8: Write the ADR**

Create `docs/adr/0004-the-dashboard-write-surface.md`. Match the structure of the existing ADRs: context, the options weighed, the decision, the consequences. It must cover, in the project's spartan prose:

- The threat model. A local process running as the user can already rewrite `config.toml`, so a write API grants it nothing and auth would be theatre. The adversary is a web page. This is CSRF.
- Why `sameOrigin` was insufficient. Loopback at any port means every proxied dev server is inside the boundary.
- The three layers, and that the origin check is the gate while the token is defence in depth.
- Why reads keep the permissive check. The break-glass path when the resolver or CA is broken.
- Why the privileged ports stay out. Root must never learn a port number from a file any local process can rewrite, per ADR 0001.
- Consequence to name honestly: anyone who can run code as this user can already do all of this. This design does not change that and does not claim to.

- [ ] **Step 9: Add the DESIGN.md decision row**

Add a row to the decisions log table in `DESIGN.md` section 2, numbered 15, following the existing format:

| 15 | Dashboard writes | **Strict origin plus a per-process CSRF token. No auth.** | A local process running as the user can already rewrite the config file, so auth would be theatre. The adversary is a web page. `sameOrigin` accepted loopback at any port, which put every proxied dev server inside the boundary. Writes now require the dashboard's own origin or loopback at the dashboard port; reads keep the permissive check because `http://127.0.0.1:8484` is the only way in when the resolver or the CA is broken. See [ADR 0004](docs/adr/0004-the-dashboard-write-surface.md) |

- [ ] **Step 10: Run everything**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: PASS.

- [ ] **Step 11: Commit**

```bash
git add internal/dashboard/origin.go internal/dashboard/origin_test.go \
        internal/dashboard/dashboard.go internal/dashboard/inspect.go \
        internal/dashboard/inspect_test.go internal/dashboard/templates/console.html \
        docs/adr/0004-the-dashboard-write-surface.md DESIGN.md
git commit -m "feat: gate mutating dashboard routes on a strict origin

sameOrigin accepted loopback at any port. That is right for reads, because
127.0.0.1:8484 is the only way in when the resolver or the CA is broken. It
is wrong for writes: every dev server this proxy sits in front of is on
loopback too, so one bad npm dependency would be inside the boundary.

Writes now need the dashboard's own origin, or loopback at the dashboard
port. A per-process CSRF token sits behind that as defence in depth.

handleInspectClear is the only mutating route today, so it is what proves
the machinery before any config write exists to use it. The guard test walks
routes() and fails if a mutating entry skips the wrapper, and fails outright
if it finds no mutating routes at all."
```

---

### Task 6: Write plumbing and POST /api/routes

**Files:**
- Modify: `internal/dashboard/configapi.go` (the `withConfig` helper)
- Create: `internal/dashboard/routesapi.go`
- Modify: `internal/dashboard/dashboard.go` (one `routes()` entry)
- Test: `internal/dashboard/routesapi_test.go`

**Interfaces:**
- Consumes: `config.LoadWithVersion` (Task 1), `pathsOr503` (Task 2), `writeConfigView` (Task 4), `mutate` (Task 5).
- Produces: `(*Server).withConfig(w http.ResponseWriter, wantVersion string, edit func(*config.Config) error) bool`. Tasks 7 and 8 both route every write through it.

- [ ] **Step 1: Write the failing tests**

Create `internal/dashboard/routesapi_test.go`:

```go
package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

const baseConfig = "suffix = \"test\"\n\n[[routes]]\ndomain = \"app.test\"\nport = 3000\n"

// write drives a mutating endpoint with a correct origin and token, so each
// test is about the endpoint's own behavior and not about the guard, which
// origin_test.go already covers exhaustively.
func write(t *testing.T, s *Server, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = "switchboard.test"
	req.Header.Set("Origin", "https://switchboard.test")
	req.Header.Set(csrfHeader, s.csrf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.mux().ServeHTTP(w, req)
	return w
}

func TestAddRouteWritesTheFile(t *testing.T) {
	s, path := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "POST", "/api/routes",
		`{"domain":"api","port":4000,"version":"`+version+`"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d, want 201: %s", w.Code, w.Body)
	}

	// The response is the new config, so a client never needs a follow-up
	// read to find out what happened.
	var out readConfigView
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Routes) != 2 {
		t.Fatalf("response has %d routes, want 2", len(out.Routes))
	}
	if out.Version == version {
		t.Error("the version did not change after a write")
	}

	// And it is actually on disk, because the daemon reloads from the file
	// and not from anything this handler holds.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "api.test") {
		t.Errorf("the file does not contain the new route:\n%s", b)
	}
}

// A bare name gets the suffix appended, the same way `switchboard add` does.
// Two ways to add a route that disagree about naming would be worse than
// having only one.
func TestAddRouteNormalizesABareName(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "POST", "/api/routes",
		`{"domain":"api","port":4000,"version":"`+version+`"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var out readConfigView
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, r := range out.Routes {
		if r.Domain == "api.test" {
			return
		}
	}
	t.Errorf("no api.test route: %+v", out.Routes)
}

func TestAddRouteRejectsAStaleVersion(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)

	w := write(t, s, "POST", "/api/routes",
		`{"domain":"api","port":4000,"version":"0000000000000000"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409: %s", w.Code, w.Body)
	}

	// The 409 carries the current config, so the client re-renders without a
	// second round trip.
	var out readConfigView
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("409 body is not a config view: %v", err)
	}
	if out.Version == "" || len(out.Routes) != 1 {
		t.Errorf("409 body should be the current config, got %+v", out)
	}
}

func TestAddRouteRejectsADuplicate(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "POST", "/api/routes",
		`{"domain":"app.test","port":9999,"version":"`+version+`"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422: %s", w.Code, w.Body)
	}
}

func TestAddRouteRejectsTheReservedDashboardName(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "POST", "/api/routes",
		`{"domain":"switchboard.test","port":9999,"version":"`+version+`"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422: %s", w.Code, w.Body)
	}
}

func TestAddRouteRejectsBadJSON(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	if w := write(t, s, "POST", "/api/routes", "{{{"); w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", w.Code)
	}
}

// Two writes racing at the same version. Exactly one must win, and the
// loser must be told rather than silently dropped. This is the whole reason
// the version exists, so it gets a real concurrency test and not a comment.
func TestConcurrentWritesAtTheSameVersionProduceOneWinner(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i, domain := range []string{"one", "two"} {
		wg.Add(1)
		go func(i int, domain string) {
			defer wg.Done()
			w := write(t, s, "POST", "/api/routes",
				`{"domain":"`+domain+`","port":4000,"version":"`+version+`"}`)
			codes[i] = w.Code
		}(i, domain)
	}
	wg.Wait()

	var created, conflicted int
	for _, c := range codes {
		switch c {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflicted++
		default:
			t.Errorf("unexpected status %d", c)
		}
	}
	if created != 1 || conflicted != 1 {
		t.Fatalf("got %d created and %d conflicted, want exactly one of each", created, conflicted)
	}

	// And the file must hold exactly one of them, not a torn merge.
	if got := len(getConfig(t, s).Routes); got != 2 {
		t.Fatalf("%d routes on disk, want 2 (the original plus one winner)", got)
	}
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `go test ./internal/dashboard/ -run 'AddRoute|Concurrent' -v`
Expected: FAIL, 404 on POST.

- [ ] **Step 3: Add the write helper**

Append to `internal/dashboard/configapi.go` (add `"sync"` to its imports):

```go
// writeMu serializes config writes from this process.
//
// It cannot serialize against the CLI, which does its own read-modify-write
// on the same file. That is what the version is for. A CLI write between a
// client's read and its write is caught by the version compare below. A CLI
// write inside this critical section is not, but that window is microseconds
// and the CLI is human paced. Named here so nobody mistakes it for an
// oversight and reaches for a lock file.
var writeMu sync.Mutex

// withConfig runs edit against a freshly read config, under the write lock,
// and saves the result. Every write endpoint goes through it, so no
// individual handler can forget the version guard.
//
// A stale version answers 409 with the current config in the body. The
// client has to re-render anyway, and making it fetch again is a round trip
// for information this response is already holding.
//
// Returns whether the write succeeded. On false it has already answered.
func (s *Server) withConfig(w http.ResponseWriter, wantVersion string, edit func(*config.Config) error) bool {
	p, ok := s.pathsOr503(w)
	if !ok {
		return false
	}

	writeMu.Lock()
	defer writeMu.Unlock()

	cfg, version, err := config.LoadWithVersion(p.configPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	if wantVersion != version {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(s.newConfigView(cfg, version)) //nolint:errcheck
		return false
	}
	if err := edit(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return false
	}
	// Validate explicitly before Save. Save validates too, but it returns
	// one error for both a bad edit and a filesystem failure, and those are
	// a 422 and a 500 respectively.
	if err := cfg.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return false
	}
	if err := cfg.Save(p.configPath); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	return true
}

// decodeBody reads a JSON request body with a size cap. A config write is
// never large, and an uncapped decoder on a loopback listener is still an
// uncapped decoder.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(v); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return false
	}
	return true
}
```

- [ ] **Step 4: Implement the endpoint**

Create `internal/dashboard/routesapi.go`:

```go
// Route writes. Split from configapi.go because routes are a list with their
// own identity and naming rules, while the rest of the config is scalar
// fields. They change for different reasons.
package dashboard

import (
	"fmt"
	"net/http"

	"github.com/alsey89/switchboard/internal/config"
)

// routeBody is the wire shape for creating or editing a route. Port and
// Upstream mirror config.Route, where exactly one of the two is set and
// Validate enforces it.
type routeBody struct {
	Domain   string `json:"domain"`
	Port     int    `json:"port"`
	Upstream string `json:"upstream"`
	Version  string `json:"version"`
}

func (s *Server) handleRouteCreate(w http.ResponseWriter, r *http.Request) {
	var in routeBody
	if !decodeBody(w, r, &in) {
		return
	}
	ok := s.withConfig(w, in.Version, func(cfg *config.Config) error {
		// NormalizeDomain is what `switchboard add` uses. Two ways to add a
		// route that disagreed about bare names would be worse than one.
		// It also rejects the reserved dashboard name.
		domain, err := config.NormalizeDomain(in.Domain, cfg.Suffix)
		if err != nil {
			return err
		}
		for _, rt := range cfg.Routes {
			if rt.Domain == domain {
				return fmt.Errorf("%s already has a route", domain)
			}
		}
		cfg.Routes = append(cfg.Routes, config.Route{
			Domain: domain, Port: in.Port, Upstream: in.Upstream,
		})
		return nil
	})
	if !ok {
		return
	}
	s.writeConfigView(w, http.StatusCreated)
}
```

Add to `routes()` in `dashboard.go`, directly after the `/api/config` entry:

```go
		{method: "POST", pattern: "/api/routes",
			handler: s.guard(s.mutate(s.handleRouteCreate)), guarded: true, mutating: true},
```

The existing `{pattern: "/api/routes", ...}` entry stays. Go's `ServeMux` prefers the more specific method-qualified pattern for POST and falls through to the method-less one for GET.

- [ ] **Step 5: Confirm the 201 carries a content type**

`writeConfigView` takes the status so it can set `Content-Type` before writing it. Setting a header after `WriteHeader` is a silent no-op, so this would otherwise send a correct JSON body with no content type and nothing would fail.

Run: `go test ./internal/dashboard/ -run AddRouteWritesTheFile -v 2>&1 | grep -i superfluous`
Expected: no output.

Then assert it in the test rather than trusting a grep. Add to `TestAddRouteWritesTheFile`, after the status check:

```go
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type %q, want application/json", ct)
	}
```

- [ ] **Step 6: Run the tests**

Run: `go test ./internal/dashboard/ -run 'AddRoute|Concurrent' -v`
Expected: PASS, all seven.

- [ ] **Step 7: Run with the race detector**

Run: `go test ./internal/dashboard/ -race -run Concurrent -v`
Expected: PASS with no race reported. This is the one test where a race would be a real bug rather than test noise.

- [ ] **Step 8: Run everything**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/dashboard/configapi.go internal/dashboard/routesapi.go \
        internal/dashboard/routesapi_test.go internal/dashboard/dashboard.go
git commit -m "feat: add routes from the dashboard

Writes go through the config file, not the running proxy, so the fsnotify
watcher applies them exactly as it applies a hand edit. The GUI and a text
editor behave identically, which is the property worth protecting.

Every write carries the version of the file it read. A stale write gets a
409 carrying the current config, so the client re-renders in one round trip
instead of two. The mutex serializes this process; the version is what
covers the CLI, which does its own read-modify-write on the same file."
```

---

### Task 7: PATCH and DELETE on a route

**Files:**
- Modify: `internal/dashboard/routesapi.go`
- Modify: `internal/dashboard/dashboard.go` (two `routes()` entries)
- Test: `internal/dashboard/routesapi_test.go`

**Interfaces:**
- Consumes: `withConfig`, `decodeBody`, `routeBody` (Task 6).
- Produces: `PATCH /api/routes/{domain}` and `DELETE /api/routes/{domain}`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/dashboard/routesapi_test.go`:

```go
func TestEditRouteChangesTheUpstream(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "PATCH", "/api/routes/app.test",
		`{"port":5000,"version":"`+version+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}

	out := getConfig(t, s)
	if len(out.Routes) != 1 {
		t.Fatalf("%d routes, want 1", len(out.Routes))
	}
	// localhost, not 127.0.0.1. Route.UpstreamAddr resolves a bare port via
	// net.JoinHostPort("localhost", port). Only an explicitly set upstream
	// comes back verbatim.
	if out.Routes[0].Upstream != "localhost:5000" {
		t.Errorf("upstream %q, want localhost:5000", out.Routes[0].Upstream)
	}
}

// Renaming has to clear the old shorthand as well as set the new one.
// Leaving Port set while Upstream is also set makes Validate reject the
// whole config, which would be a confusing 422 on the next unrelated write.
func TestEditRouteSwitchingToAnUpstreamClearsThePort(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "PATCH", "/api/routes/app.test",
		`{"upstream":"127.0.0.1:6000","version":"`+version+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}
	if got := getConfig(t, s).Routes[0].Upstream; got != "127.0.0.1:6000" {
		t.Errorf("upstream %q", got)
	}
}

func TestEditRouteRenamesTheDomain(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "PATCH", "/api/routes/app.test",
		`{"domain":"web","version":"`+version+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}
	if got := getConfig(t, s).Routes[0].Domain; got != "web.test" {
		t.Errorf("domain %q, want web.test", got)
	}
}

func TestEditUnknownRouteIs404(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "PATCH", "/api/routes/nope.test",
		`{"port":5000,"version":"`+version+`"}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404: %s", w.Code, w.Body)
	}
}

func TestDeleteRouteRemovesIt(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "DELETE", "/api/routes/app.test?version="+version, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}
	if got := len(getConfig(t, s).Routes); got != 0 {
		t.Fatalf("%d routes left, want 0", got)
	}
}

func TestDeleteUnknownRouteIs404(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "DELETE", "/api/routes/nope.test?version="+version, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404: %s", w.Code, w.Body)
	}
}

func TestDeleteRouteRejectsAStaleVersion(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	w := write(t, s, "DELETE", "/api/routes/app.test?version=0000000000000000", "")
	if w.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409", w.Code)
	}
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `go test ./internal/dashboard/ -run 'EditRoute|DeleteRoute|EditUnknown|DeleteUnknown' -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

Append to `internal/dashboard/routesapi.go`:

```go
// findRoute returns the index of domain in cfg.Routes, or -1.
func findRoute(cfg *config.Config, domain string) int {
	for i, rt := range cfg.Routes {
		if rt.Domain == domain {
			return i
		}
	}
	return -1
}

// routeDomainFromPath pulls the domain out of /api/routes/<domain>. Returns
// "" for a bare /api/routes/ with nothing after it.
func routeDomainFromPath(p string) string {
	return strings.TrimPrefix(p, "/api/routes/")
}

// routeExists reports whether domain currently has a route.
//
// This lookup happens before withConfig, not inside it. Inside, the only way
// to signal "no such route" is to return an error, and withConfig has
// already written a 422 by the time the handler could correct it. A missing
// route is a 404. Doing the lookup first is the only way to say so.
//
// The read is unlocked and could go stale, but withConfig re-checks under
// the lock and answers 409 if the file moved. The worst case is a 404 for a
// route deleted microseconds ago, which is the right answer anyway.
func (s *Server) routeExists(domain string) (bool, bool) {
	p := s.paths.Load()
	if p == nil {
		return false, false
	}
	cfg, _, err := config.LoadWithVersion(p.configPath)
	if err != nil {
		return false, false
	}
	return findRoute(cfg, domain) >= 0, true
}

func (s *Server) handleRouteEdit(w http.ResponseWriter, r *http.Request) {
	target := routeDomainFromPath(r.URL.Path)
	var in routeBody
	if !decodeBody(w, r, &in) {
		return
	}
	if found, ok := s.routeExists(target); ok && !found {
		http.Error(w, "no route for "+target, http.StatusNotFound)
		return
	}

	ok := s.withConfig(w, in.Version, func(cfg *config.Config) error {
		i := findRoute(cfg, target)
		if i < 0 {
			return fmt.Errorf("no route for %s", target)
		}
		if in.Domain != "" {
			domain, err := config.NormalizeDomain(in.Domain, cfg.Suffix)
			if err != nil {
				return err
			}
			if j := findRoute(cfg, domain); j >= 0 && j != i {
				return fmt.Errorf("%s already has a route", domain)
			}
			cfg.Routes[i].Domain = domain
		}
		// Exactly one of Port and Upstream may be set, so setting either one
		// must clear the other. Leaving both would make Validate reject the
		// whole config, and the user would see a 422 about a field they did
		// not touch.
		switch {
		case in.Upstream != "":
			cfg.Routes[i].Upstream = in.Upstream
			cfg.Routes[i].Port = 0
		case in.Port != 0:
			cfg.Routes[i].Port = in.Port
			cfg.Routes[i].Upstream = ""
		}
		return nil
	})
	if !ok {
		return
	}
	s.writeConfigView(w, http.StatusOK)
}

func (s *Server) handleRouteDelete(w http.ResponseWriter, r *http.Request) {
	target := routeDomainFromPath(r.URL.Path)
	if found, ok := s.routeExists(target); ok && !found {
		http.Error(w, "no route for "+target, http.StatusNotFound)
		return
	}

	ok := s.withConfig(w, r.URL.Query().Get("version"), func(cfg *config.Config) error {
		i := findRoute(cfg, target)
		if i < 0 {
			return fmt.Errorf("no route for %s", target)
		}
		cfg.Routes = append(cfg.Routes[:i], cfg.Routes[i+1:]...)
		return nil
	})
	if !ok {
		return
	}
	// 200 with the new config, not 204. The client needs the new version to
	// make its next write, and a 204 would force an immediate read to get it.
	s.writeConfigView(w, http.StatusOK)
}
```

Add `"strings"` to the imports. `"errors"` is not needed: every failure path here uses `fmt.Errorf`.

Add to `routes()` in `dashboard.go`:

```go
		{method: "PATCH", pattern: "/api/routes/",
			handler: s.guard(s.mutate(s.handleRouteEdit)), guarded: true, mutating: true},
		{method: "DELETE", pattern: "/api/routes/",
			handler: s.guard(s.mutate(s.handleRouteDelete)), guarded: true, mutating: true},
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/dashboard/ -run 'Route' -v`
Expected: PASS, all of them, including Task 6's.

- [ ] **Step 5: Run everything, with race**

Run: `go build ./... && go vet ./... && go test ./... -race`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/dashboard/routesapi.go internal/dashboard/routesapi_test.go internal/dashboard/dashboard.go
git commit -m "feat: edit and delete routes from the dashboard

The lookup happens before the write helper runs, so a missing route is a 404
rather than the helper's blanket 422. That read is unlocked and can go
stale, but the write re-checks under the lock and answers 409 if the file
moved, so the worst case is a 404 for a route deleted microseconds ago.

Setting a port clears the upstream and vice versa. Exactly one of the two
may be set, and leaving both would fail validation on a field the user never
touched."
```

---

### Task 8: PATCH /api/config

**Files:**
- Modify: `internal/dashboard/configapi.go`
- Modify: `internal/dashboard/dashboard.go` (one `routes()` entry)
- Test: `internal/dashboard/configapi_test.go`

**Interfaces:**
- Consumes: `withConfig`, `decodeBody` (Task 6).
- Produces: `PATCH /api/config`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/dashboard/configapi_test.go`:

```go
func TestPatchConfigSetsDashboardPort(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "PATCH", "/api/config",
		`{"dashboardPort":9000,"version":"`+version+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}
	out := getConfig(t, s)
	if out.Effective.DashboardPort != 9000 {
		t.Errorf("dashboard port %d, want 9000", out.Effective.DashboardPort)
	}
}

func TestPatchConfigTurnsTheInspectorOff(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "PATCH", "/api/config",
		`{"inspect":{"enabled":false},"version":"`+version+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}
	if getConfig(t, s).Inspect.Enabled {
		t.Error("inspector should be off")
	}
}

// Omitting a field must leave it alone. A settings form that sends one
// changed field should not silently reset the rest, which is exactly what a
// plain bool would do here.
func TestPatchConfigLeavesOmittedFieldsAlone(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	if w := write(t, s, "PATCH", "/api/config",
		`{"inspect":{"bodies":true},"version":"`+version+`"}`); w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	out := getConfig(t, s)
	if !out.Inspect.Bodies {
		t.Error("bodies should be on")
	}
	if !out.Inspect.Enabled {
		t.Error("enabled should still be on; it was not in the request")
	}
	if len(out.Routes) != 1 {
		t.Error("routes should be untouched")
	}
}

// The privileged ports and the suffix are not writable here. They need sudo
// or a resolver rewrite, and this endpoint accepting them would silently do
// nothing, which is worse than refusing.
func TestPatchConfigRefusesTheSudoTier(t *testing.T) {
	for _, body := range []string{
		`{"httpsPort":8443,"version":"%s"}`,
		`{"httpPort":8080,"version":"%s"}`,
		`{"dnsPort":5454,"version":"%s"}`,
		`{"suffix":"internal","version":"%s"}`,
	} {
		t.Run(body, func(t *testing.T) {
			s, _ := serverWithPaths(t, baseConfig)
			version := getConfig(t, s).Version
			w := write(t, s, "PATCH", "/api/config", strings.Replace(body, "%s", version, 1))
			if w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status %d, want 422: %s", w.Code, w.Body)
			}
			if !strings.Contains(w.Body.String(), "switchboard") {
				t.Errorf("the error should name the CLI command to use, got: %s", w.Body)
			}
		})
	}
}

func TestPatchConfigRejectsAStaleVersion(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	w := write(t, s, "PATCH", "/api/config",
		`{"dashboardPort":9000,"version":"0000000000000000"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409", w.Code)
	}
}
```

Add `"strings"` to `configapi_test.go`'s imports.

- [ ] **Step 2: Run them and watch them fail**

Run: `go test ./internal/dashboard/ -run PatchConfig -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

Append to `internal/dashboard/configapi.go`:

```go
// configPatch is the wire shape for a settings change.
//
// Every field is a pointer so an absent field is distinguishable from a zero
// one. A settings form that sends one changed field must not silently reset
// everything it left out, and a plain bool cannot express that.
//
// The sudo-tier fields are present on purpose. They are refused with an
// explanation naming the CLI command, which is a better answer than a
// silently ignored field or a 400 that does not say why.
type configPatch struct {
	Version string `json:"version"`

	DashboardPort *int `json:"dashboardPort"`

	Inspect *struct {
		Enabled      *bool   `json:"enabled"`
		Bodies       *bool   `json:"bodies"`
		MaxRequests  *int    `json:"maxRequests"`
		MaxBytes     *int64  `json:"maxBytes"`
		MaxBodyBytes *int    `json:"maxBodyBytes"`
		MaxAge       *string `json:"maxAge"`
	} `json:"inspect"`

	// Refused. See sudoTierRefusal.
	Suffix    *string `json:"suffix"`
	HTTPPort  *int    `json:"httpPort"`
	HTTPSPort *int    `json:"httpsPort"`
	DNSPort   *int    `json:"dnsPort"`
}

// sudoTierRefusal explains why a field cannot be set here and what to run
// instead. These are not arbitrary exclusions:
//
//   - suffix rewrites /etc/resolver and re-issues the CA. Both need sudo,
//     and the CA also needs a keychain authorization.
//   - dns_port is written into the resolver file, so changing it means
//     rewriting a root-owned file.
//   - http_port and https_port do nothing under a launch daemon. The
//     privileged parent hardcodes 443 and 80, because root must never learn
//     a port number from a file any local process can rewrite. See ADR 0001.
func sudoTierRefusal(field string) error {
	switch field {
	case "suffix":
		return errors.New("the suffix rewrites /etc/resolver and re-issues the CA, " +
			"so it needs sudo. Run: switchboard suffix <new-suffix>")
	case "dns_port":
		return errors.New("the DNS port is written into /etc/resolver, so changing it " +
			"needs sudo. Set dns_port in the config file, then run: switchboard setup")
	default:
		return errors.New("the HTTP and HTTPS ports are bound by the privileged parent " +
			"and cannot be set from here. Set them in the config file, then run: " +
			"switchboard daemon install")
	}
}

func (s *Server) handleConfigPatch(w http.ResponseWriter, r *http.Request) {
	var in configPatch
	if !decodeBody(w, r, &in) {
		return
	}
	ok := s.withConfig(w, in.Version, func(cfg *config.Config) error {
		switch {
		case in.Suffix != nil:
			return sudoTierRefusal("suffix")
		case in.DNSPort != nil:
			return sudoTierRefusal("dns_port")
		case in.HTTPPort != nil, in.HTTPSPort != nil:
			return sudoTierRefusal("ports")
		}
		if in.DashboardPort != nil {
			cfg.DashboardPort = *in.DashboardPort
		}
		if in.Inspect != nil {
			if cfg.Inspect == nil {
				cfg.Inspect = &config.InspectConfig{}
			}
			p, c := in.Inspect, cfg.Inspect
			if p.Enabled != nil {
				c.Enabled = p.Enabled
			}
			if p.Bodies != nil {
				c.Bodies = *p.Bodies
			}
			if p.MaxRequests != nil {
				c.MaxRequests = *p.MaxRequests
			}
			if p.MaxBytes != nil {
				c.MaxBytes = *p.MaxBytes
			}
			if p.MaxBodyBytes != nil {
				c.MaxBodyBytes = *p.MaxBodyBytes
			}
			if p.MaxAge != nil {
				c.MaxAge = *p.MaxAge
			}
		}
		return nil
	})
	if !ok {
		return
	}
	s.writeConfigView(w, http.StatusOK)
}
```

Add `"errors"` to `configapi.go`'s imports.

Add to `routes()` in `dashboard.go`, after the existing `/api/config` entry:

```go
		{method: "PATCH", pattern: "/api/config",
			handler: s.guard(s.mutate(s.handleConfigPatch)), guarded: true, mutating: true},
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/dashboard/ -run PatchConfig -v`
Expected: PASS, all five including the four sudo-tier subtests.

- [ ] **Step 5: Run everything**

Run: `go build ./... && go vet ./... && go test ./... -race`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/dashboard/configapi.go internal/dashboard/configapi_test.go internal/dashboard/dashboard.go
git commit -m "feat: edit settings from the dashboard

Every patch field is a pointer, so omitting a field leaves it alone. A
settings form sending one changed value must not reset everything else, and
a plain bool cannot tell unset from false.

The suffix and the three non-dashboard ports are refused with an error
naming the command to run instead. They need sudo or a resolver rewrite.
Accepting them and doing nothing would be worse than refusing, which is
exactly what setting https_port does today under a launch daemon."
```

---

### Task 9: Report whether a saved change is actually running

The last piece. `Validate` passing is not `proxy.Load` succeeding, so a write can return 200 and the daemon can still be serving the old config.

**Files:**
- Modify: `internal/dashboard/dashboard.go` (`applied` field, `SetApplied`, bound port)
- Modify: `internal/dashboard/configapi.go` (`configView` fields)
- Modify: `internal/daemon/daemon.go:99-103, 254-281`
- Test: `internal/dashboard/configapi_test.go`

**Interfaces:**
- Consumes: everything above.
- Produces: `(*Server).SetApplied(version string, err error)`. The daemon calls it after every load attempt, including the first.

- [ ] **Step 1: Write the failing tests**

Append to `internal/dashboard/configapi_test.go`:

```go
// A config nobody has told the dashboard about yet is not claimed to be
// running. Reporting applied:true by default would make the banner useless
// in exactly the case it exists for.
func TestAppliedIsFalseUntilTheDaemonSaysOtherwise(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	if getAppliedView(t, s).Applied {
		t.Error("applied should be false before any reload is reported")
	}
}

func TestAppliedIsTrueForTheVersionTheDaemonLoaded(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version
	s.SetApplied(version, nil)

	got := getAppliedView(t, s)
	if !got.Applied {
		t.Error("applied should be true for the version the daemon loaded")
	}
	if got.ApplyError != "" {
		t.Errorf("applyError %q, want empty", got.ApplyError)
	}
}

// A write moves the file ahead of the daemon. Until the watcher catches up,
// the dashboard must say so rather than imply the change is live.
func TestAppliedGoesFalseAfterAWrite(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version
	s.SetApplied(version, nil)

	if w := write(t, s, "POST", "/api/routes",
		`{"domain":"api","port":4000,"version":"`+version+`"}`); w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if getAppliedView(t, s).Applied {
		t.Error("applied should be false: the file moved and no reload was reported")
	}
}

// A reload that failed has to surface. Today it only reaches the log, where
// nobody is looking, and that is true for hand edits as well as for writes.
func TestApplyErrorSurfaces(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version
	s.SetApplied(version, errors.New("proxy reload exploded"))

	got := getAppliedView(t, s)
	if got.Applied {
		t.Error("applied should be false when the reload failed")
	}
	if !strings.Contains(got.ApplyError, "exploded") {
		t.Errorf("applyError %q should carry the reason", got.ApplyError)
	}
}

func TestRestartRequiredWhenTheDashboardPortMoved(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	// Start records the port it actually bound. Simulate that without
	// binding, so the test does not need a free port.
	s.boundPort = 8484

	if getAppliedView(t, s).RestartRequired {
		t.Error("no restart needed: the config port matches the bound port")
	}

	version := getConfig(t, s).Version
	if w := write(t, s, "PATCH", "/api/config",
		`{"dashboardPort":9000,"version":"`+version+`"}`); w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if !getAppliedView(t, s).RestartRequired {
		t.Error("restart should be required: the saved port is not the bound port")
	}
}

type appliedView struct {
	Applied         bool   `json:"applied"`
	ApplyError      string `json:"applyError"`
	RestartRequired bool   `json:"restartRequired"`
}

func getAppliedView(t *testing.T, s *Server) appliedView {
	t.Helper()
	w := do(s, "GET", "/api/config", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var out appliedView
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
```

Add `"errors"` to `configapi_test.go`'s imports.

- [ ] **Step 2: Run them and watch them fail**

Run: `go test ./internal/dashboard/ -run 'Applied|ApplyError|RestartRequired' -v`
Expected: FAIL, `s.SetApplied undefined`.

- [ ] **Step 3: Add the state to the Server**

In `internal/dashboard/dashboard.go`, add to the `Server` struct:

```go
	// applied is the outcome of the daemon's last config load.
	//
	// Save only runs Validate, and proxy.Load can fail for reasons Validate
	// does not model, so a write can succeed and the daemon can still be
	// serving the previous config. Rather than making writes synchronous,
	// the reload reports itself and the dashboard says whether the file and
	// the running daemon agree.
	applied atomic.Pointer[applyState]

	// boundPort is the port Start actually listened on. Compared against the
	// configured port to know whether a restart is pending.
	boundPort int
```

And below `SetPaths`:

```go
type applyState struct {
	version string
	err     error
}

// SetApplied records the outcome of a config load. The daemon calls it after
// every attempt, successful or not, including the one at startup.
func (s *Server) SetApplied(version string, err error) {
	s.applied.Store(&applyState{version: version, err: err})
}
```

In `Start`, after the listener is created, record the port:

```go
	if _, port, splitErr := net.SplitHostPort(ln.Addr().String()); splitErr == nil {
		s.boundPort, _ = strconv.Atoi(port)
	}
```

Add `"strconv"` to `dashboard.go`'s imports.

- [ ] **Step 4: Extend `configView`**

In `internal/dashboard/configapi.go`, add three fields to `configView`:

```go
	Applied         bool   `json:"applied"`
	ApplyError      string `json:"applyError,omitempty"`
	RestartRequired bool   `json:"restartRequired"`
```

And set them at the end of `newConfigView`, before the return. Restructure it to build the value then decorate:

```go
	v := configView{ /* ... existing fields ... */ }

	// Applied means the running daemon is serving this exact file. Absent
	// any report it is false, not true: claiming a config is live when
	// nothing has confirmed it makes the banner useless in the one case it
	// exists for.
	if a := s.applied.Load(); a != nil {
		v.Applied = a.version == version && a.err == nil
		if a.err != nil {
			v.ApplyError = a.err.Error()
		}
	}

	// The dashboard cannot rebind its own listener mid-request without
	// killing the request it is answering, so a port change is a banner and
	// a button, not something that happens on save.
	v.RestartRequired = s.boundPort != 0 && cfg.EffDashboardPort() != s.boundPort

	return v
```

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/dashboard/ -run 'Applied|ApplyError|RestartRequired' -v`
Expected: PASS.

- [ ] **Step 6: Wire the daemon**

In `internal/daemon/daemon.go`, change the initial load at line 99 to capture the version:

```go
	cfg, cfgVersion, err := config.LoadWithVersion(opts.ConfigPath)
	if err != nil {
		return err
	}
```

After `dash.SetPaths(...)` from Task 2, add:

```go
	dash.SetApplied(cfgVersion, nil)
```

Then in the reload case (line 254 onward), change the load and report both outcomes:

```go
		case <-reload:
			next, nextVersion, err := config.LoadWithVersion(opts.ConfigPath)
			if err != nil {
				log.Error("config reload failed; keeping previous config", "err", err)
				// No version to report: the file did not parse, so there is
				// nothing to say is applied. The dashboard keeps showing the
				// last good one as stale, which is accurate.
				continue
			}
			if next.Suffix != cfg.Suffix {
				log.Error("suffix changed; restart the daemon (and re-run setup) to apply",
					"old", cfg.Suffix, "new", next.Suffix)
				dash.SetApplied(nextVersion, errors.New(
					"the suffix changed; restart the daemon and re-run setup to apply it"))
				continue
			}
			if err := proxy.Load(next, opts.DataDir, set); err != nil {
				log.Error("proxy reload failed; keeping previous config", "err", err)
				dash.SetApplied(nextVersion, err)
				continue
			}
			cfg = next
			dash.SetConfig(next)
			ensureInspector(next)
			dash.SetApplied(nextVersion, nil)
			log.Info("config reloaded", "routes", len(cfg.Routes))
```

Add `"errors"` to `daemon.go`'s imports if it is not already there.

- [ ] **Step 7: Run everything**

Run: `go build ./... && go vet ./... && go test ./... -race`
Expected: PASS.

- [ ] **Step 8: Manual smoke test**

This is the first point where the whole thing is real. Do it.

```bash
go build -o /tmp/switchboard ./cmd/switchboard
/tmp/switchboard start &
sleep 2
curl -s http://127.0.0.1:8484/api/doctor | head -20
curl -s http://127.0.0.1:8484/api/config
```

Then confirm a write is refused without an origin, and accepted with one. Take the token from the page:

```bash
TOKEN=$(curl -s http://127.0.0.1:8484/ | grep switchboard-csrf | sed 's/.*content="\([^"]*\)".*/\1/')
VERSION=$(curl -s http://127.0.0.1:8484/api/config | sed 's/.*"version":"\([^"]*\)".*/\1/')

# No origin: must be 403.
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8484/api/routes \
  -H "X-Switchboard-CSRF: $TOKEN" -d "{\"domain\":\"smoke\",\"port\":4321,\"version\":\"$VERSION\"}"

# Correct origin: must be 201.
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8484/api/routes \
  -H "Origin: http://127.0.0.1:8484" -H "X-Switchboard-CSRF: $TOKEN" \
  -d "{\"domain\":\"smoke\",\"port\":4321,\"version\":\"$VERSION\"}"
```

Expected: `403` then `201`. Then confirm the daemon picked it up, which proves the fsnotify path applies a GUI write with no new machinery:

```bash
sleep 1
curl -s http://127.0.0.1:8484/api/config | grep -o '"applied":[a-z]*'
```

Expected: `"applied":true`. Then clean up: `kill %1` and remove the smoke route from the config.

- [ ] **Step 9: Commit**

```bash
git add internal/dashboard/dashboard.go internal/dashboard/configapi.go \
        internal/dashboard/configapi_test.go internal/daemon/daemon.go
git commit -m "feat: report whether the saved config is the running one

Save only runs Validate. proxy.Load can fail for reasons Validate does not
model, so a write can return 200 while the daemon keeps serving the old
config. Making writes synchronous would not fix that, because a hand edit
has the same problem and no request to block.

So the reload reports itself instead. The dashboard compares the file
version against the last one the daemon loaded and says whether they agree.
This also surfaces a failed reload from a hand edit, which until now only
reached the log."
```

---

## Self-Review

**Spec coverage.** Walked each spec section:

| Spec section | Task |
|---|---|
| Threat model, three layers | 5 |
| Enforced by construction | 5 |
| API: `GET /api/config` | 4, extended in 9 |
| API: `GET /api/doctor` | 2 |
| API: `GET /api/service` | 3 |
| API: route writes | 6, 7 |
| API: `PATCH /api/config` | 8 |
| API: `/api/inspect/clear` to strict origin | 5 |
| Version hash, `LoadWithVersion` | 1 |
| Applying a change, the five steps | 6 |
| Saved is not running | 9 |
| `restartRequired` | 9 |
| The sudo tier | 8, refusals naming the CLI command |
| Frontend | Plan 2 |
| Build and CI | Plan 2 |
| Testing, Go half | Every task |
| Testing, Vitest half | Plan 2 |
| What must not regress | Plan 2, except `go install` which this plan cannot break |
| Docs: ADR 0004, DESIGN.md decision row | 5 |
| Docs: DESIGN.md decision 7 rewrite, roadmap | Plan 2, where the framework actually arrives |

**Gap found and closed.** The spec's config redaction note (relay tokens once tunnels land) has no task, correctly: there is nothing to redact yet. It is recorded in the spec and belongs to the tunnels work.

**Type consistency.** `configView` is built by `newConfigView` and written by `writeConfigView` in every task that returns config. `routeView` is the existing type from `dashboard.go` and is reused, not redefined. `withConfig`'s signature is fixed in Task 6 and unchanged by Tasks 7 and 8. `csrfHeader` is a constant used by both `origin.go` and the test helper. `paths` is the struct, `s.paths` the field, `pathsOr503` the accessor, consistent throughout.

**Trap worth naming.** The obvious way to write Task 7's handlers is to do the route lookup inside `withConfig` and return an error when it misses. That produces a 422 where a 404 belongs, and it cannot be corrected afterwards because `withConfig` has already written the response. Task 7 does the lookup first for exactly this reason, and the comment on `routeExists` says so.
