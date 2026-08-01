package proxy

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/caddyserver/caddy/v2"

	"github.com/alsey89/switchboard/internal/listen"
)

// Caddy binds its own sockets from the `listen` addresses in its config,
// which is a problem when the socket was handed to us by a privileged parent
// and cannot be re-bound. Caddy's escape hatch is RegisterNetwork: an address
// of the form "<network>/host:port" is resolved by a registered function
// instead of net.Listen.
//
// So inherited sockets appear in the generated config as
// "sbinherit/127.0.0.1:443", and the function below returns the descriptor we
// already hold. Nothing else about the config changes, which keeps the two
// modes from diverging into two code paths.
const inheritedNetwork = "sbinherit"

// inheritedByAddr maps "host:port" to the listener to serve it. Populated by
// registerInherited before caddy.Load and read by the network function during
// it. A package-level map is the shape Caddy's API forces — registration is
// global and takes no user data.
var inheritedByAddr sync.Map

func init() {
	caddy.RegisterNetwork(inheritedNetwork, func(_ context.Context, _, host, portRange string, portOffset uint, _ net.ListenConfig) (any, error) {
		port, err := strconv.Atoi(portRange)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a single port", inheritedNetwork, portRange)
		}
		addr := net.JoinHostPort(host, strconv.Itoa(port+int(portOffset)))
		v, ok := inheritedByAddr.Load(addr)
		if !ok {
			return nil, fmt.Errorf("no inherited socket for %s — the privileged parent "+
				"did not pass this address", addr)
		}
		// One generation per config load. The descriptor is still never
		// closed, but the previous generation stops accepting — see
		// listen.Handoff for why both halves are required.
		return v.(*listen.Handoff).Next(), nil
	})
}

// registerInherited publishes the sockets in set under the addresses the
// generated config will name, and reports the address to use for each socket.
// A socket that was not inherited keeps its plain address, so Caddy binds it
// the ordinary way.
func registerInherited(set *listen.Set, want map[string]string) map[string]string {
	addrs := make(map[string]string, len(want))
	for name, plain := range want {
		if !set.Inherited(name) {
			addrs[name] = plain
			continue
		}
		actual := set.Addr(name)
		// One Handoff per socket, for the life of the process. Making a new
		// one per reload would start a second accept loop on the same
		// descriptor, which is the thing the Handoff exists to prevent.
		if _, ok := inheritedByAddr.Load(actual); !ok {
			ln, _ := set.Listen(name, "") // cannot fail: it is inherited
			inheritedByAddr.Store(actual, listen.NewHandoff(ln))
		}
		addrs[name] = inheritedNetwork + "/" + actual
	}
	return addrs
}
