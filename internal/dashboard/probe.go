package dashboard

import (
	"net"
	"sync"
	"time"
)

const (
	probeTimeout = 300 * time.Millisecond

	// probeTTL is half the console's ten second poll interval, so a route
	// that comes up shows within one tick and never two.
	probeTTL = 5 * time.Second
)

type probeResult struct {
	up bool
	at time.Time
}

// prober answers "is anything listening at this address" for a set of
// upstreams at once, and remembers each answer for ttl.
//
// The concurrency is what pays now that the console refreshes routes on a
// timer: the old code dialed serially, so five down routes cost 1.5 seconds
// on every tick.
//
// The cache almost never hits, and that is by design. The rail is server
// rendered on load, and the page's only other call is the ten second tick,
// which is always past the TTL. The TTL still has a job: it is the ceiling
// on how stale an answer a burst of calls can share, so raising it above the
// tick interval would break the "a route that comes up shows within one
// tick" promise. Do not raise it because the cache looks idle.
//
// now and dial are fields rather than direct calls so tests can drive the
// clock and count dials without opening a socket.
type prober struct {
	ttl  time.Duration
	now  func() time.Time
	dial func(addr string) bool

	mu   sync.Mutex
	seen map[string]probeResult
}

func newProber(ttl time.Duration) *prober {
	return &prober{
		ttl:  ttl,
		now:  time.Now,
		dial: dialTCP,
		seen: map[string]probeResult{},
	}
}

func dialTCP(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return false
	}
	c.Close() //nolint:errcheck
	return true
}

// statuses reports up or down for every address in addrs. It dials only the
// ones with no fresh cached answer, dials those in parallel, and dials a
// repeated address once.
//
// addrs must be the complete set of upstreams, not a subset. Anything cached
// that addrs does not name is treated as a route that left the config and is
// dropped, so asking about one route would throw away the answers for all
// the others. Both callers go through routeViews, which passes the whole
// config; a new caller has to do the same.
func (p *prober) statuses(addrs []string) map[string]bool {
	now := p.now()
	out := make(map[string]bool, len(addrs))
	todo := make(map[string]struct{})

	p.mu.Lock()
	for _, a := range addrs {
		if r, ok := p.seen[a]; ok && now.Sub(r.at) < p.ttl {
			out[a] = r.up
			continue
		}
		todo[a] = struct{}{}
	}
	p.mu.Unlock()

	// No early return when todo is empty: the removed-upstream cleanup below
	// must still run even on an all-cache-hit call, or an address dropped
	// from the config lingers in p.seen for as long as its neighbors keep
	// getting probed.
	var (
		wg    sync.WaitGroup
		fmu   sync.Mutex
		fresh = make(map[string]bool, len(todo))
	)
	for a := range todo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			up := p.dial(a)
			fmu.Lock()
			fresh[a] = up
			fmu.Unlock()
		}()
	}
	wg.Wait()

	stamp := p.now()
	p.mu.Lock()
	for a, up := range fresh {
		out[a] = up
		p.seen[a] = probeResult{up: up, at: stamp}
	}
	// Anything cached that is not in this call's address list is a route
	// that has since been removed.
	for a := range p.seen {
		if _, ok := out[a]; !ok {
			delete(p.seen, a)
		}
	}
	p.mu.Unlock()

	return out
}
