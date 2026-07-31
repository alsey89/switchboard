// Package dnsd implements the tiny authoritative DNS responder that makes
// names under the managed suffix resolve to 127.0.0.1 (e.g. *.test). The OS
// is pointed at it via /etc/resolver on macOS (with a `port` directive, so
// no fight over :53), NRPT on Windows, and split-DNS on Linux.
//
// Behavioral notes, learned from prior art (see DESIGN.md §4):
//
//   - Every name under the managed suffix gets an A record, even unrouted
//     ones — the proxy serves a friendly "no route" page instead of the
//     browser showing a resolver error.
//   - AAAA (and other types) for managed names answer NOERROR with an empty
//     answer section (NODATA) and an SOA in AUTHORITY. Answering NXDOMAIN
//     would negative-cache the *name* and kill the A record too.
//   - Queries outside the managed suffixes are REFUSED: this server is
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

// Server answers A/AAAA queries for the managed suffixes.
type Server struct {
	suffixes []string // without leading dot, lowercase

	udp *dns.Server
	tcp *dns.Server

	// addr the UDP listener actually bound (useful when port 0 was asked).
	addr net.Addr
}

// New creates a server for the given suffixes (e.g. ["test"]).
func New(suffixes []string) *Server {
	lowered := make([]string, len(suffixes))
	for i, t := range suffixes {
		lowered[i] = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(t, "."), "."))
	}
	return &Server{suffixes: lowered}
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

	suffix, ok := s.managedSuffix(name)
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
		m.Answer = append(m.Answer, s.soa(suffix))
	case dns.TypeNS:
		m.Answer = append(m.Answer, &dns.NS{
			Hdr: dns.RR_Header{Name: suffix + ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: soaTTL},
			Ns:  "ns.switchboard." + suffix + ".",
		})
	default:
		// NODATA: NOERROR + empty answer + SOA in authority so resolvers
		// negative-cache only this type, not the name.
		m.Ns = append(m.Ns, s.soa(suffix))
	}
	w.WriteMsg(m) //nolint:errcheck
}

// managedSuffix reports whether fqdn (with trailing dot) falls under one of
// the managed suffixes, returning the matching suffix.
func (s *Server) managedSuffix(fqdn string) (string, bool) {
	trimmed := strings.TrimSuffix(fqdn, ".")
	for _, suffix := range s.suffixes {
		if trimmed == suffix || strings.HasSuffix(trimmed, "."+suffix) {
			return suffix, true
		}
	}
	return "", false
}

func (s *Server) soa(suffix string) dns.RR {
	zone := suffix + "."
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
