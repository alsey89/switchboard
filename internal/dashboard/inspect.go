package dashboard

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alsey89/switchboard/internal/inspect"
)

// recordJSON is the wire shape of a captured request. Bodies are strings
// because that is what a browser can show; captured bytes that are not valid
// UTF-8 are replaced rather than dropped, so a binary body still reads as
// "something was here" instead of vanishing.
type recordJSON struct {
	ID          int64               `json:"id"`
	StartedAt   string              `json:"started_at"`
	DurationMS  float64             `json:"duration_ms"`
	Domain      string              `json:"domain"`
	Method      string              `json:"method"`
	Path        string              `json:"path"`
	Status      int                 `json:"status"`
	Proto       string              `json:"proto"`
	Upgraded    bool                `json:"upgraded"`
	ReqBytes    int64               `json:"req_bytes"`
	RespBytes   int64               `json:"resp_bytes"`
	Error       string              `json:"error,omitempty"`
	ReqHeaders  map[string][]string `json:"req_headers,omitempty"`
	RespHeaders map[string][]string `json:"resp_headers,omitempty"`
	ReqBody     string              `json:"req_body,omitempty"`
	RespBody    string              `json:"resp_body,omitempty"`
}

func toJSON(r *inspect.Record) recordJSON {
	return recordJSON{
		ID:          r.ID,
		StartedAt:   r.StartedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		DurationMS:  float64(r.Duration.Microseconds()) / 1000,
		Domain:      r.Domain,
		Method:      r.Method,
		Path:        r.Path,
		Status:      r.Status,
		Proto:       r.Proto,
		Upgraded:    r.Upgraded,
		ReqBytes:    r.ReqBytes,
		RespBytes:   r.RespBytes,
		Error:       r.Error,
		ReqHeaders:  r.ReqHeaders,
		RespHeaders: r.RespHeaders,
		ReqBody:     string(r.ReqBody),
		RespBody:    string(r.RespBody),
	}
}

// withoutBodies strips the captured bodies from a wire record.
//
// The stream is a list feed. Its backfill comes from Store.List, which omits
// bodies by design, so a live event that carried them made the same record
// arrive in two different shapes depending on which path it took. It also
// put up to max_body_bytes on the wire twice per record, for a view that
// never renders it, and held that much per record in every subscriber's
// 256-deep channel. The page refetches the full record from the detail
// endpoint when a row is opened.
func withoutBodies(j recordJSON) recordJSON {
	j.ReqBody = ""
	j.RespBody = ""
	return j
}

// recorder returns the active recorder, or writes a 503 and reports false.
func (s *Server) recorder(w http.ResponseWriter) (*inspect.Recorder, bool) {
	rec := s.insp.Load()
	if rec == nil {
		http.Error(w, "the inspector is off", http.StatusServiceUnavailable)
		return nil, false
	}
	return rec, true
}

// storeError answers a store failure without ever putting the raw driver or
// filesystem text on the page.
//
// A reload can call SetInspector(nil) and close the store between the
// moment a handler loads the recorder pointer and the moment its query
// runs: that pointer swap is a bare atomic store with no barrier for a
// reader already in flight. database/sql's own response to a query on a
// closed *DB is "sql: database is closed" — a plain string, not an exported
// sentinel, so it is matched by substring here. Anything else is a genuine
// query failure and gets a generic 500; either way the operator sees a
// clean message, not a driver string.
func storeError(w http.ResponseWriter, err error) {
	if strings.Contains(err.Error(), "database is closed") {
		http.Error(w, "the inspector is off", http.StatusServiceUnavailable)
		return
	}
	http.Error(w, "inspector query failed", http.StatusInternalServerError)
}

func (s *Server) handleInspectRequests(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.recorder(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)

	rows, err := rec.Store().List(inspect.Query{
		Domain: q.Get("domain"),
		Method: q.Get("method"),
		Status: q.Get("status"),
		Q:      q.Get("q"),
		Before: before,
		Limit:  limit,
	})
	if err != nil {
		storeError(w, err)
		return
	}

	out := struct {
		Requests []recordJSON `json:"requests"`
		Dropped  int64        `json:"dropped"`
	}{Requests: []recordJSON{}, Dropped: rec.Dropped()}
	for _, row := range rows {
		out.Requests = append(out.Requests, toJSON(row))
	}
	writeJSON(w, out)
}

func (s *Server) handleInspectRecord(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.recorder(w)
	if !ok {
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/inspect/requests/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	row, err := rec.Store().Get(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		storeError(w, err)
		return
	}
	writeJSON(w, toJSON(row))
}

// handleInspectClear empties the buffer.
//
// This is the dashboard's only state-changing endpoint, so it states its
// rule rather than inheriting one. POST only, and Origin must be present and
// match. An absent Origin is refused rather than trusted: browsers always
// send it on fetch, so refusing absence closes the simple-request CSRF hole
// that loopback alone does not.
//
// What it destroys is captured traffic. No route, no trust setting, no
// config. When route mutation lands it will need this same check, harder.
func (s *Server) handleInspectClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	if !s.sameOrigin(r) {
		http.Error(w, "bad origin", http.StatusForbidden)
		return
	}
	rec, ok := s.recorder(w)
	if !ok {
		return
	}
	if err := rec.Store().Clear(); err != nil {
		storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// sameOrigin reports whether the request carries an Origin naming this
// dashboard. A missing Origin is not same-origin.
//
// Loopback is trusted at any port and any scheme: http://localhost:3000
// passes exactly as well as https://switchboard.test does. That is
// deliberate, not an oversight — the whole premise of switchboard is
// sitting in front of whatever dev servers are already running on
// loopback, and pinning to one port would defeat it. But it means every
// process listening on 127.0.0.1 sits inside the trust boundary for
// whatever calls sameOrigin. Today the only caller is handleInspectClear,
// so the blast radius is "can clear captured traffic" — tolerable. If a
// future mutating route (the "harder" case handleInspectClear's comment
// above anticipates) reuses sameOrigin for something with a bigger blast
// radius, this port-and-scheme-blind trust needs revisiting first.
func (s *Server) sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return false
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	host := strings.ToLower(hostOnly(u.Host))
	return host == s.cfg.Load().DashboardDomain() || isLoopbackHost(host)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// handleInspectStream is the live feed.
//
// Server-sent events, not a websocket. The feed only ever goes one way, so a
// bidirectional protocol would buy nothing and cost a dependency. SSE also
// reconnects on its own, which is what makes dropping a slow subscriber a
// safe thing to do: the browser comes back and backfills.
func (s *Server) handleInspectStream(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.recorder(w)
	if !ok {
		return
	}
	if _, ok := w.(http.Flusher); !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	rc := http.NewResponseController(w)

	// Subscribe before backfilling. The other order has a hole: a request
	// arriving between the query and the subscription is in neither. The
	// trade this makes is a duplicate, not a drop: a record that lands
	// exactly in that window arrives once in the backfill and once on the
	// channel, and a client can de-duplicate on id, since Insert assigns
	// the id before publish hands the same record to both paths.
	ch, cancel := rec.Subscribe()
	defer cancel()

	// Query before writing any header, so a closed store (a reload raced
	// this request) still gets a clean storeError response instead of a
	// stream that opened and then silently skipped the backfill.
	backfill, err := rec.Store().List(inspect.Query{Limit: 200})
	if err != nil {
		storeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return
	}

	// List is newest first; replay oldest first so the client can append.
	for i := len(backfill) - 1; i >= 0; i-- {
		sendEvent(w, toJSON(backfill[i]))
	}
	if err := rc.Flush(); err != nil {
		return
	}

	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return

		case <-s.done:
			// The server is shutting down. http.Server.Shutdown waits for
			// this handler and will not cancel r.Context() to get it, so
			// without this case an open inspector tab holds the daemon up
			// forever. See the note on Server.done.
			return

		case record, open := <-ch:
			if !open {
				// Dropped for falling behind. Closing here is the whole
				// point: EventSource reconnects and backfills.
				return
			}
			sendEvent(w, withoutBodies(toJSON(record)))
			if err := rc.Flush(); err != nil {
				return
			}

		case <-ping.C:
			io.WriteString(w, ": ping\n\n") //nolint:errcheck
			if err := rc.Flush(); err != nil {
				return
			}
		}
	}
}

func sendEvent(w http.ResponseWriter, v recordJSON) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	io.WriteString(w, "data: ") //nolint:errcheck
	w.Write(b)                  //nolint:errcheck
	io.WriteString(w, "\n\n")   //nolint:errcheck
}

// handleInspectPage serves the split-pane inspector UI. The page itself
// carries no server-rendered record data — it fetches everything from the
// JSON and SSE endpoints above, client side — so there is nothing here for
// html/template to escape.
func (s *Server) handleInspectPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.ExecuteTemplate(w, "inspect.html", nil) //nolint:errcheck
}
