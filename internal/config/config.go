// Package config defines Switchboard's user-facing configuration: a small,
// hand-editable TOML file that the CLI also rewrites. The daemon watches it
// and hot-reloads on change.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

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

	// TLD is the pre-v0.2 spelling of Suffix. Read on load so existing
	// configs keep working; Save never writes it.
	TLD string `toml:"tld,omitempty"`

	// Ports. Zero values mean defaults. These exist mainly as escape
	// hatches (port conflicts) and for tests; normal use never sets them.
	// (BurntSushi/toml omits numeric zeros via omitzero, not omitempty.)
	HTTPPort      int `toml:"http_port,omitzero"`
	HTTPSPort     int `toml:"https_port,omitzero"`
	DNSPort       int `toml:"dns_port,omitzero"`
	DashboardPort int `toml:"dashboard_port,omitzero"`

	Routes []Route `toml:"routes"`
}

// Route maps a local domain to a local upstream. Exactly one of Port or
// Upstream is set; Port is shorthand for 127.0.0.1:<port>.
type Route struct {
	Domain   string `toml:"domain"`
	Port     int    `toml:"port,omitzero"`
	Upstream string `toml:"upstream,omitempty"`
}

// Defaults, exported for use in docs/tests.
const (
	DefaultSuffix        = "test"
	DefaultHTTPPort      = 80
	DefaultHTTPSPort     = 443
	DefaultDNSPort       = 53535
	DefaultDashboardPort = 8484
)

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

// Load reads and validates the config at path. A missing file yields the
// default config (not an error): the tool should work before `add` runs.
func Load(path string) (*Config, error) {
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
	// Migrate the pre-v0.2 `tld` key. Save() only ever writes `suffix`, so a
	// load+save cycle rewrites the file in the new spelling.
	if c.Suffix == "" {
		c.Suffix = c.TLD
	}
	c.TLD = ""
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
	seen := map[string]bool{}
	for i := range c.Routes {
		r := &c.Routes[i]
		norm, err := NormalizeDomain(r.Domain, c.Suffix)
		if err != nil {
			return fmt.Errorf("route %q: %w", r.Domain, err)
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

// UpstreamAddr returns the dial address for the route.
func (r *Route) UpstreamAddr() string {
	if r.Upstream != "" {
		return r.Upstream
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(r.Port))
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
	// A multi-label suffix is a domain the user is asserting they own.
	// Scoping the resolver to it cannot collide with anyone else's names.
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

// FindRoute returns the route for domain, if any.
func (c *Config) FindRoute(domain string) (Route, bool) {
	for _, r := range c.Routes {
		if r.Domain == domain {
			return r, true
		}
	}
	return Route{}, false
}
