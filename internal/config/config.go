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
	// TLD is the managed top-level domain, without a leading dot.
	TLD string `toml:"tld"`

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
	DefaultTLD           = "test"
	DefaultHTTPPort      = 80
	DefaultHTTPSPort     = 443
	DefaultDNSPort       = 53535
	DefaultDashboardPort = 8484
)

func Default() *Config {
	return &Config{TLD: DefaultTLD}
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
	if c.TLD == "" {
		c.TLD = DefaultTLD
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
	if err := validateTLD(c.TLD); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i := range c.Routes {
		r := &c.Routes[i]
		norm, err := NormalizeDomain(r.Domain, c.TLD)
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

// NormalizeDomain lowercases, strips any trailing dot, appends the TLD when
// the name is bare (no dot), and validates the result: it must be a proper
// subdomain of the managed TLD and must not be the reserved dashboard name.
func NormalizeDomain(domain, tld string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if d == "" {
		return "", errors.New("empty domain")
	}
	if !strings.Contains(d, ".") {
		d = d + "." + tld
	}
	suffix := "." + tld
	if !strings.HasSuffix(d, suffix) {
		return "", fmt.Errorf("domain must end in %s", suffix)
	}
	if d == suffix[1:] || strings.TrimSuffix(d, suffix) == "" {
		return "", fmt.Errorf("domain needs a label before %s", suffix)
	}
	if d == Reserved+suffix {
		return "", fmt.Errorf("%s is reserved for the Switchboard dashboard", d)
	}
	for _, label := range strings.Split(d, ".") {
		if !validLabel(label) {
			return "", fmt.Errorf("invalid domain label %q", label)
		}
	}
	return d, nil
}

func validateTLD(tld string) error {
	if tld == "" || strings.Contains(tld, ".") || !validLabel(tld) {
		return fmt.Errorf("invalid tld %q", tld)
	}
	if tld == "local" {
		return errors.New("tld \"local\" collides with mDNS (RFC 6762); use \"test\"")
	}
	if tld == "dev" {
		return errors.New("tld \"dev\" is a real, HSTS-preloaded gTLD; use \"test\"")
	}
	return nil
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
func (c *Config) DashboardDomain() string { return Reserved + "." + c.TLD }

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
