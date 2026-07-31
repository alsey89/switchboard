// Package dnsd implements the tiny authoritative DNS responder that makes
// *.test resolve to 127.0.0.1. The OS is pointed at it via /etc/resolver
// on macOS (with a `port` directive, so no fight over :53), NRPT on
// Windows, and split-DNS on Linux.
//
// Behavioral notes, learned from prior art (see DESIGN.md §4):
//
//   - Every name under a managed TLD gets an A record, even unrouted ones —
//     the proxy serves a friendly "no route" page instead of the browser
//     showing a resolver error.
//   - AAAA (and other types) for managed names answer NOERROR with an empty
//     answer section (NODATA) and an SOA in AUTHORITY. Answering NXDOMAIN
//     would negative-cache the *name* and kill the A record too.
//   - Queries outside the managed TLDs are REFUSED: this server is
//     authoritative-only and must never be mistaken for a recursor.
package dnsd

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	answerTTL = 10 // seconds; dev routes change often, keep caches short
	soaTTL    = 60
)

// Server answers A/AAAA queries for the managed TLDs.
type Server struct {
	tlds []string // without leading dot, lowercase

	udp *dns.Server
	tcp *dns.Server

	// addr the UDP listener actually bound (useful when port 0 was asked).
	addr net.Addr
}

// New creates a server for the given TLDs (e.g. ["test"]).
func New(tlds []string) *Server {
	lowered := make([]string, len(tlds))
	for i, t := range tlds {
		lowered[i] = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(t, "."), "."))
	}
	return &Server{tlds: lowered}
}

// Start binds UDP and TCP listeners on bind (e.g. "127.0.0.1:53535") and
// serves until Shutdown. It returns once both listeners are ready.
func (s *Server) Start(bind string) error {
	pc, err := net.ListenPacket("udp", bind)
	if err != nil {
		return fmt.Errorf("dns: udp listen %s: %w", bind, err)
	}
	s.addr = pc.LocalAddr()

	// TCP on the same port the UDP socket got (matters when bind used :0).
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		return fmt.Errorf("dns: tcp listen %s: %w", pc.LocalAddr(), err)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handle)

	s.udp = &dns.Server{PacketConn: pc, Handler: mux}
	s.tcp = &dns.Server{Listener: ln, Handler: mux}

	go s.udp.ActivateAndServe() //nolint:errcheck // exits on Shutdown
	go s.tcp.ActivateAndServe() //nolint:errcheck
	return nil
}

// Addr returns the bound UDP address (nil before Start).
func (s *Server) Addr() net.Addr { return s.addr }

// Shutdown stops both listeners.
func (s *Server) Shutdown(ctx context.Context) error {
	var first error
	for _, srv := range []*dns.Server{s.udp, s.tcp} {
		if srv == nil {
			continue
		}
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		if err := srv.ShutdownContext(c); err != nil && first == nil {
			first = err
		}
		cancel()
	}
	return first
}

func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true

	if len(req.Question) == 0 {
		m.Rcode = dns.RcodeFormatError
		w.WriteMsg(m) //nolint:errcheck
		return
	}
	q := req.Question[0]
	name := strings.ToLower(q.Name) // FQDN with trailing dot

	tld, ok := s.managedTLD(name)
	if !ok {
		// Not ours: refuse, never recurse.
		m.Rcode = dns.RcodeRefused
		m.Authoritative = false
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	switch q.Qtype {
	case dns.TypeA:
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: answerTTL},
			A:   net.IPv4(127, 0, 0, 1),
		})
	case dns.TypeSOA:
		m.Answer = append(m.Answer, s.soa(tld))
	case dns.TypeNS:
		m.Answer = append(m.Answer, &dns.NS{
			Hdr: dns.RR_Header{Name: tld + ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: soaTTL},
			Ns:  "ns.switchboard." + tld + ".",
		})
	default:
		// NODATA: NOERROR + empty answer + SOA in authority so resolvers
		// negative-cache only this type, not the name.
		m.Ns = append(m.Ns, s.soa(tld))
	}
	w.WriteMsg(m) //nolint:errcheck
}

// managedTLD reports whether fqdn (with trailing dot) falls under one of the
// managed TLDs, returning the matching TLD.
func (s *Server) managedTLD(fqdn string) (string, bool) {
	trimmed := strings.TrimSuffix(fqdn, ".")
	for _, tld := range s.tlds {
		if trimmed == tld || strings.HasSuffix(trimmed, "."+tld) {
			return tld, true
		}
	}
	return "", false
}

func (s *Server) soa(tld string) dns.RR {
	zone := tld + "."
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: soaTTL},
		Ns:      "ns.switchboard." + zone,
		Mbox:    "hostmaster.switchboard." + zone,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  soaTTL,
	}
}
