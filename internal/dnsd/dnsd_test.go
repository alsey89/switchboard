package dnsd

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startTestServer(t *testing.T) string {
	t.Helper()
	s := New([]string{"test"})
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) }) //nolint:errcheck
	return s.Addr().String()
}

func query(t *testing.T, addr, name string, qtype uint16, net string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	c := &dns.Client{Net: net, Timeout: 2 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query %s %d: %v", name, qtype, err)
	}
	return resp
}

func TestARecordForManagedTLD(t *testing.T) {
	addr := startTestServer(t)
	for _, name := range []string{"app.test", "deeply.nested.sub.test", "UPPER.test"} {
		resp := query(t, addr, name, dns.TypeA, "udp")
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("%s: rcode %v", name, dns.RcodeToString[resp.Rcode])
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("%s: want 1 answer, got %d", name, len(resp.Answer))
		}
		a, ok := resp.Answer[0].(*dns.A)
		if !ok || a.A.String() != "127.0.0.1" {
			t.Fatalf("%s: want A 127.0.0.1, got %v", name, resp.Answer[0])
		}
		if !resp.Authoritative {
			t.Errorf("%s: response should be authoritative", name)
		}
	}
}

// AAAA must be NODATA (NOERROR + no answers + SOA in authority), never
// NXDOMAIN: NXDOMAIN would negative-cache the whole name and kill the A
// record too. This is the DNS gotcha from DESIGN.md §4.
func TestAAAAIsNodataNotNxdomain(t *testing.T) {
	addr := startTestServer(t)
	resp := query(t, addr, "app.test", dns.TypeAAAA, "udp")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("AAAA rcode = %v, must be NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("AAAA must have no answers, got %v", resp.Answer)
	}
	if len(resp.Ns) == 0 {
		t.Fatal("NODATA response should carry an SOA in the authority section")
	}
	if _, ok := resp.Ns[0].(*dns.SOA); !ok {
		t.Fatalf("authority record should be SOA, got %T", resp.Ns[0])
	}
}

func TestRefusesUnmanagedNames(t *testing.T) {
	addr := startTestServer(t)
	for _, name := range []string{"example.com", "test.example.org", "attest.example"} {
		resp := query(t, addr, name, dns.TypeA, "udp")
		if resp.Rcode != dns.RcodeRefused {
			t.Errorf("%s: rcode = %v, want REFUSED (never recurse, never answer)",
				name, dns.RcodeToString[resp.Rcode])
		}
	}
}

// "attest" must not match ".test" by sloppy suffix logic.
func TestNoFalseSuffixMatch(t *testing.T) {
	addr := startTestServer(t)
	resp := query(t, addr, "attest", dns.TypeA, "udp")
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("bare 'attest' matched managed TLD: rcode %v", dns.RcodeToString[resp.Rcode])
	}
}

func TestTCPWorksToo(t *testing.T) {
	addr := startTestServer(t)
	resp := query(t, addr, "app.test", dns.TypeA, "tcp")
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("tcp query failed: %+v", resp)
	}
}

func TestMultiLabelSuffix(t *testing.T) {
	s := New([]string{"dev.example.com"})
	for _, name := range []string{"app.dev.example.com.", "api.app.dev.example.com.", "dev.example.com."} {
		if _, ok := s.managedSuffix(name); !ok {
			t.Errorf("%s should be managed", name)
		}
	}
	// The parent domain and unrelated names must not be captured.
	for _, name := range []string{"example.com.", "www.example.com.", "notdev.example.com."} {
		if _, ok := s.managedSuffix(name); ok {
			t.Errorf("%s should NOT be managed", name)
		}
	}
}
