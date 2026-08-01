package proxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/listen"
)

// handlerIDs returns the "handler" value of each handler in each route of
// the https server, in order.
func handlerIDs(t *testing.T, cfg *config.Config, dir string) [][]string {
	t.Helper()
	cc, err := Generate(cfg, dir, &listen.Set{})
	if err != nil {
		t.Fatal(err)
	}
	var apps struct {
		HTTP struct {
			Servers map[string]struct {
				Routes []struct {
					Handle []map[string]json.RawMessage `json:"handle"`
				} `json:"routes"`
			} `json:"servers"`
		} `json:"http"`
	}
	raw, err := json.Marshal(map[string]json.RawMessage{"http": cc.AppsRaw["http"]})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &apps); err != nil {
		t.Fatal(err)
	}
	var out [][]string
	for _, rt := range apps.HTTP.Servers["https"].Routes {
		var ids []string
		for _, h := range rt.Handle {
			var id string
			if err := json.Unmarshal(h["handler"], &id); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		out = append(out, ids)
	}
	return out
}

func TestInspectHandlerRunsBeforeTheProxyOnUserRoutes(t *testing.T) {
	cfg := &config.Config{Suffix: "test", Routes: []config.Route{{Domain: "app.test", Port: 3000}}}
	got := handlerIDs(t, cfg, t.TempDir())

	if len(got) != 2 {
		t.Fatalf("got %d routes, want the user route plus the dashboard catch-all", len(got))
	}
	want := []string{"switchboard_inspect", "reverse_proxy"}
	if strings.Join(got[0], ",") != strings.Join(want, ",") {
		t.Errorf("user route handlers = %v, want %v", got[0], want)
	}
}

func TestInspectHandlerIsNotOnTheDashboardCatchAll(t *testing.T) {
	cfg := &config.Config{Suffix: "test", Routes: []config.Route{{Domain: "app.test", Port: 3000}}}
	got := handlerIDs(t, cfg, t.TempDir())

	last := got[len(got)-1]
	for _, id := range last {
		if id == "switchboard_inspect" {
			t.Fatal("the catch-all is the dashboard; instrumenting it makes the inspector record itself, feed included")
		}
	}
}

func TestInspectHandlerAbsentWhenDisabled(t *testing.T) {
	off := false
	cfg := &config.Config{
		Suffix:  "test",
		Inspect: &config.InspectConfig{Enabled: &off},
		Routes:  []config.Route{{Domain: "app.test", Port: 3000}},
	}
	for _, route := range handlerIDs(t, cfg, t.TempDir()) {
		for _, id := range route {
			if id == "switchboard_inspect" {
				t.Fatal("disabled means not in the config at all, not inserted and idle")
			}
		}
	}
}
