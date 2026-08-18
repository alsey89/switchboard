// Package config defines Switchboard's user-facing configuration: a small,
// hand-editable TOML file that the CLI also rewrites. The daemon watches it
// and hot-reloads on change.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Reserved is the host label reserved for the built-in dashboard
// (e.g. switchboard.test).
const Reserved = "switchboard"

// Config is the root of the TOML file.
type Config struct {
	// Suffix is the managed domain suffix, without a leading dot. Either a
	// reserved TLD (see ReservedSuffixes) or a domain the user owns
	// (e.g. "dev.example.com").
	Suffix string `toml:"suffix"`

	// Ports. Zero values mean defaults. These are escape hatches for port
	// conflicts; normal use never sets them.
	//
	// http_port and https_port apply only when the daemon binds its own
	// sockets. Started by the privileged parent, it is handed :443 and :80
	// already bound and these two settings do nothing — the daemon logs a
	// warning saying so. This is deliberate and is the security boundary of
	// the whole design: root must never learn a port number from a file any
	// local process can rewrite, or a hostile config makes it bind an
	// unclaimed privileged port (631, 88, 548) and hand the descriptor over.
	// See internal/privileged and docs/adr/0001.
	// (BurntSushi/toml omits numeric zeros via omitzero, not omitempty.)
	HTTPPort      int `toml:"http_port,omitzero"`
	HTTPSPort     int `toml:"https_port,omitzero"`
	DNSPort       int `toml:"dns_port,omitzero"`
	DashboardPort int `toml:"dashboard_port,omitzero"`

	// Inspect configures the request inspector. Absent means defaults,
	// which is metadata capture on and bodies off.
	Inspect *InspectConfig `toml:"inspect,omitempty"`

	Routes []Route `toml:"routes"`
}

// Route maps a local domain to a local upstream. Exactly one of Port or
// Upstream is set; Port is shorthand for 127.0.0.1:<port>.
type Route struct {
	Domain   string `toml:"domain"`
	Port     int    `toml:"port,omitzero"`
	Upstream string `toml:"upstream,omitempty"`
}

// InspectConfig configures the request inspector. A nil *InspectConfig and a
// zero-valued one both mean "all defaults", so the accessors below are the
// only supported way to read these.
type InspectConfig struct {
	// Enabled turns metadata capture on or off. Pointer, not bool: the
	// default is true, and a plain bool cannot tell "unset" from "off".
	Enabled *bool `toml:"enabled,omitempty"`

	// Bodies captures request and response bodies. It also stops header
	// redaction. Both effects, not one: someone who asked for the payload
	// has already asked for the credentials in it, and a redacted Cookie
	// next to a full session body is a confusing half measure.
	Bodies bool `toml:"bodies,omitzero"`

	MaxRequests  int   `toml:"max_requests,omitzero"`
	MaxBytes     int64 `toml:"max_bytes,omitzero"`
	MaxBodyBytes int   `toml:"max_body_bytes,omitzero"`

	// MaxAge is a Go duration string. It is the one knob here that is not a
	// number, because "168h" is checkable at a glance and 604800 is not.
	MaxAge string `toml:"max_age,omitempty"`
}

// Defaults, exported for use in docs/tests.
const (
	DefaultSuffix        = "test"
	DefaultHTTPPort      = 80
	DefaultHTTPSPort     = 443
	DefaultDNSPort       = 53535
	DefaultDashboardPort = 8484

	DefaultInspectMaxRequests  = 5000
	DefaultInspectMaxBytes     = 64 << 20 // 64 MiB
	DefaultInspectMaxBodyBytes = 64 << 10 // 64 KiB
)

// DefaultInspectMaxAge bounds how long captured traffic sits on disk. The
// row and byte caps cannot catch the quiet case: a lightly used route
// leaves a handful of rows that nothing ever pushes out.
const DefaultInspectMaxAge = 7 * 24 * time.Hour

func Default() *Config {
	return &Config{Suffix: DefaultSuffix}
}

// Dir returns the Switchboard config directory (~/.config/switchboard),
// honoring SWITCHBOARD_DIR for tests and unusual setups.
func Dir() (string, error) {
	if d := os.Getenv("SWITCHBOARD_DIR"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".config", "switchboard"), nil
}

// Path returns the config file path.
func Path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.toml"), nil
}

// DataDir returns the daemon state directory (Caddy storage, PKI).
// Kept under the config dir so `rm -rf ~/.config/switchboard` is a full reset.
func DataDir() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "data"), nil
}

// LoadLenient reads the config without requiring routes to match the suffix.
//
// It exists for exactly one caller: the command that changes the suffix. Once
// someone edits `suffix` by hand, Load fails — every route now ends in the
// wrong domain — and that failure takes `add`, `ls`, `doctor` and the suffix
// command itself down with it. The tool that repairs the situation cannot be
// the one that refuses to read it.
func LoadLenient(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if _, err := toml.Decode(string(b), &c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if c.Suffix == "" {
		c.Suffix = DefaultSuffix
	}
	return &c, validateSuffix(c.Suffix)
}

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

// Save writes the config atomically (write temp + rename), creating the
// directory if needed.
func (c *Config) Save(path string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var sb strings.Builder
	sb.WriteString("# Switchboard configuration. Managed by `switchboard add/rm`,\n")
	sb.WriteString("# but safe to edit by hand — the daemon hot-reloads this file.\n\n")
	if err := toml.NewEncoder(&sb).Encode(c); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Validate checks the whole config for consistency.
func (c *Config) Validate() error {
	if err := validateSuffix(c.Suffix); err != nil {
		return err
	}
	if err := c.validatePorts(); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i := range c.Routes {
		r := &c.Routes[i]
		norm, err := NormalizeDomain(r.Domain, c.Suffix)
		if err != nil {
			// The overwhelmingly likely cause is an edited `suffix` with the
			// routes left behind, and the generic "must end in" message does
			// not suggest that — it reads as a typo in one route. Name the
			// command that migrates all of them at once.
			return fmt.Errorf("route %q does not match suffix .%s: %w\n"+
				"  If you changed the suffix, migrate the routes with it:\n"+
				"    switchboard suffix %s", r.Domain, c.Suffix, err, c.Suffix)
		}
		r.Domain = norm
		if seen[norm] {
			return fmt.Errorf("duplicate route for %s", norm)
		}
		seen[norm] = true
		if err := r.validateUpstream(); err != nil {
			return fmt.Errorf("route %s: %w", norm, err)
		}
	}
	if err := c.Inspect.validate(); err != nil {
		return fmt.Errorf("inspect: %w", err)
	}
	return nil
}

// validatePorts rejects a port number no listener could ever take.
//
// Only the impossible range, deliberately. A port below 1024 is refusable
// where the refusal can be undone, which is the dashboard's PATCH endpoint
// and not here: this runs on every load, so rejecting a low port would turn
// a config someone already has into one the daemon will not read at all.
// Out of range is different. There is no machine on which 70000 works, so
// no existing config can be relying on it, and catching it at load time is
// what stops the daemon starting up only to die on net.Listen.
//
// Zero is not a port here, it is the field unset, and every unset port
// resolves to its default through the Eff accessors.
func (c *Config) validatePorts() error {
	for _, p := range []struct {
		key   string
		value int
	}{
		{"http_port", c.HTTPPort},
		{"https_port", c.HTTPSPort},
		{"dns_port", c.DNSPort},
		{"dashboard_port", c.DashboardPort},
	} {
		if p.value != 0 && (p.value < 1 || p.value > 65535) {
			return fmt.Errorf("%s %d is out of range: a port is 1-65535", p.key, p.value)
		}
	}
	return nil
}

func (r *Route) validateUpstream() error {
	switch {
	case r.Port != 0 && r.Upstream != "":
		return errors.New("set either port or upstream, not both")
	case r.Port != 0:
		if r.Port < 1 || r.Port > 65535 {
			return fmt.Errorf("port %d out of range", r.Port)
		}
	case r.Upstream != "":
		host, port, err := net.SplitHostPort(r.Upstream)
		if err != nil {
			return fmt.Errorf("upstream %q must be host:port: %w", r.Upstream, err)
		}
		if host == "" {
			return fmt.Errorf("upstream %q missing host", r.Upstream)
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("upstream %q has invalid port", r.Upstream)
		}
	default:
		return errors.New("missing port or upstream")
	}
	return nil
}

func (i *InspectConfig) validate() error {
	if i == nil {
		return nil
	}
	if i.MaxRequests < 0 {
		return fmt.Errorf("max_requests %d cannot be negative", i.MaxRequests)
	}
	if i.MaxBytes < 0 {
		return fmt.Errorf("max_bytes %d cannot be negative", i.MaxBytes)
	}
	if i.MaxBodyBytes < 0 {
		return fmt.Errorf("max_body_bytes %d cannot be negative", i.MaxBodyBytes)
	}
	if i.MaxAge != "" {
		d, err := time.ParseDuration(i.MaxAge)
		if err != nil {
			return fmt.Errorf("max_age %q is not a duration (try \"168h\"): %w", i.MaxAge, err)
		}
		if d <= 0 {
			return fmt.Errorf("max_age %q must be positive", i.MaxAge)
		}
	}
	return nil
}

// UpstreamAddr returns the dial address for the route.
//
// The port shorthand resolves through "localhost" rather than 127.0.0.1.
// Those are different addresses — 127.0.0.1 is IPv4, ::1 is IPv6 — and a
// server listening on one does not answer on the other. Node dev servers
// commonly bind IPv6 loopback only, so 127.0.0.1 produced a route that was
// dead from the moment it was added. `ls` reported it as `down`, the same
// word it uses for a server that is not running at all, which points away
// from the cause rather than at it.
//
// A name lets Go's dialer try both families and take whichever answers
// (RFC 6555). That is what a browser does when the user checks
// localhost:3000, sees their app, and reasonably concludes the problem is
// Switchboard.
//
// Upstream is returned exactly as typed. Someone who names an address means
// that address, and guessing on their behalf is what this fixes.
func (r *Route) UpstreamAddr() string {
	if r.Upstream != "" {
		return r.Upstream
	}
	return net.JoinHostPort("localhost", strconv.Itoa(r.Port))
}

// NormalizeDomain lowercases, strips any trailing dot, appends the suffix
// when the name is bare (no dot), and validates the result: it must be a
// proper subdomain of the managed suffix and must not be the reserved
// dashboard name.
func NormalizeDomain(domain, suffix string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if d == "" {
		return "", errors.New("empty domain")
	}
	if !strings.Contains(d, ".") {
		d = d + "." + suffix
	}
	dotSuffix := "." + suffix
	if !strings.HasSuffix(d, dotSuffix) {
		return "", fmt.Errorf("domain must end in %s", dotSuffix)
	}
	if d == dotSuffix[1:] || strings.TrimSuffix(d, dotSuffix) == "" {
		return "", fmt.Errorf("domain needs a label before %s", dotSuffix)
	}
	if d == Reserved+dotSuffix {
		return "", fmt.Errorf("%s is reserved for the Switchboard dashboard", d)
	}
	for _, label := range strings.Split(d, ".") {
		if !validLabel(label) {
			return "", fmt.Errorf("invalid domain label %q", label)
		}
	}
	return d, nil
}

// ReservedSuffixes are the single-label suffixes that are guaranteed never
// to be delegated to a real registry: RFC 6761 special-use names, plus
// .internal, which ICANN reserved for private use in 2024. Any other bare
// TLD is — or could become — a real one, and pointing the OS resolver at it
// would hijack real sites machine-wide.
var ReservedSuffixes = []string{"test", "internal", "localhost"}

// footguns explains the suffixes people reach for first and shouldn't.
var footguns = map[string]string{
	"dev": "is a real gTLD that Google sells: pointing the OS resolver at it would send " +
		"go.dev, web.dev and *.workers.dev to 127.0.0.1 machine-wide. " +
		"HSTS is not the problem — Switchboard serves real HTTPS — the namespace collision is",
	"app":   "is a real gTLD that Google sells",
	"local": "collides with mDNS/Bonjour (RFC 6762)",
	"home":  "is not reserved; RFC 8375 reserves \"home.arpa\" instead, which Switchboard accepts",
}

func validateSuffix(s string) error {
	if s == "" {
		return errors.New("missing suffix (e.g. suffix = \"test\")")
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if !validLabel(l) {
			return fmt.Errorf("invalid suffix %q: bad label %q", s, l)
		}
	}
	// A multi-label suffix is a domain the user is *asserting* they own.
	// This rule moves the collision risk onto them; it does not eliminate
	// it. "co.uk", "com.au" and "github.io" all pass here, and writing
	// /etc/resolver/co.uk would hijack that whole namespace machine-wide.
	// Distinguishing a registrable domain from a public suffix requires the
	// Public Suffix List — a new dependency, which this project's
	// no-new-modules constraint rules out — and the list is a moving target
	// that would then need vendoring and refreshing. So the check stays
	// structural, and the honest framing is "you told us you own this",
	// not "this cannot collide".
	if len(labels) > 1 {
		return nil
	}
	for _, r := range ReservedSuffixes {
		if s == r {
			return nil
		}
	}
	suggestion := fmt.Sprintf("use one of: %s — or a subdomain of a domain you own, "+
		"e.g. \"dev.example.com\"", strings.Join(ReservedSuffixes, ", "))
	if why, ok := footguns[s]; ok {
		return fmt.Errorf("suffix %q %s; %s", s, why, suggestion)
	}
	return fmt.Errorf("suffix %q is not a reserved name: it is, or could become, a real "+
		"top-level domain, and pointing the OS resolver at it would hijack real sites "+
		"machine-wide; %s", s, suggestion)
}

func validLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 || strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return false
	}
	for _, r := range s {
		ok := r == '-' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// Effective port helpers.

func (c *Config) EffHTTPPort() int      { return orDefault(c.HTTPPort, DefaultHTTPPort) }
func (c *Config) EffHTTPSPort() int     { return orDefault(c.HTTPSPort, DefaultHTTPSPort) }
func (c *Config) EffDNSPort() int       { return orDefault(c.DNSPort, DefaultDNSPort) }
func (c *Config) EffDashboardPort() int { return orDefault(c.DashboardPort, DefaultDashboardPort) }

func orDefault(v, d int) int {
	if v == 0 {
		return d
	}
	return v
}

// Inspector settings. Read these, never the struct: the zero value of every
// field means "default", and Enabled defaults to true.

func (c *Config) InspectEnabled() bool {
	if c.Inspect == nil || c.Inspect.Enabled == nil {
		return true
	}
	return *c.Inspect.Enabled
}

func (c *Config) InspectBodies() bool {
	return c.Inspect != nil && c.Inspect.Bodies
}

func (c *Config) InspectMaxRequests() int {
	if c.Inspect == nil {
		return DefaultInspectMaxRequests
	}
	return orDefault(c.Inspect.MaxRequests, DefaultInspectMaxRequests)
}

func (c *Config) InspectMaxBytes() int64 {
	if c.Inspect == nil || c.Inspect.MaxBytes == 0 {
		return DefaultInspectMaxBytes
	}
	return c.Inspect.MaxBytes
}

func (c *Config) InspectMaxBodyBytes() int {
	if c.Inspect == nil {
		return DefaultInspectMaxBodyBytes
	}
	return orDefault(c.Inspect.MaxBodyBytes, DefaultInspectMaxBodyBytes)
}

// InspectMaxAge returns the parsed max_age. Validate has already proved the
// string parses, so a bad value here can only come from a Config built in
// code, and falling back to the default beats panicking in the daemon.
func (c *Config) InspectMaxAge() time.Duration {
	if c.Inspect == nil || c.Inspect.MaxAge == "" {
		return DefaultInspectMaxAge
	}
	d, err := time.ParseDuration(c.Inspect.MaxAge)
	if err != nil || d <= 0 {
		return DefaultInspectMaxAge
	}
	return d
}

// DashboardDomain returns the reserved dashboard host for this config.
func (c *Config) DashboardDomain() string { return Reserved + "." + c.Suffix }

// Domains returns all explicitly-routed domains plus the dashboard domain,
// sorted, for use as eager TLS subjects.
func (c *Config) Domains() []string {
	out := []string{c.DashboardDomain()}
	for _, r := range c.Routes {
		out = append(out, r.Domain)
	}
	sort.Strings(out)
	return out
}

// SetRoute installs r, replacing any existing route for the same domain, and
// reports the route it replaced.
//
// Replacing rather than refusing: pointing a name at a different port is the
// most common thing anyone does after adding it, and `add` used to answer
// that with an error telling you to run `rm` first. A domain resolves to
// exactly one upstream, so a second `add` for the same name has only one
// possible meaning.
func (c *Config) SetRoute(r Route) (previous Route, replaced bool) {
	for i := range c.Routes {
		if c.Routes[i].Domain == r.Domain {
			previous, c.Routes[i] = c.Routes[i], r
			return previous, true
		}
	}
	c.Routes = append(c.Routes, r)
	return Route{}, false
}

// FindRoute returns the route for domain, if any.
func (c *Config) FindRoute(domain string) (Route, bool) {
	for _, r := range c.Routes {
		if r.Domain == domain {
			return r, true
		}
	}
	return Route{}, false
}
