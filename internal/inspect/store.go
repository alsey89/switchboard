package inspect

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, registered as "sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS requests (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at   INTEGER NOT NULL,
  duration_us  INTEGER NOT NULL,
  domain       TEXT    NOT NULL,
  method       TEXT    NOT NULL,
  path         TEXT    NOT NULL,
  status       INTEGER NOT NULL,
  proto        TEXT    NOT NULL,
  upgraded     INTEGER NOT NULL DEFAULT 0,
  req_bytes    INTEGER NOT NULL DEFAULT 0,
  resp_bytes   INTEGER NOT NULL DEFAULT 0,
  error        TEXT    NOT NULL DEFAULT '',
  req_headers  TEXT    NOT NULL DEFAULT '{}',
  resp_headers TEXT    NOT NULL DEFAULT '{}',
  req_body     BLOB,
  resp_body    BLOB,
  size_bytes   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_requests_started ON requests(started_at);
`

// rowOverhead approximates the fixed cost of a row's scalar columns against
// the byte cap. It does not have to be exact. It has to stop a buffer of
// millions of tiny rows from reporting itself as nearly empty.
const rowOverhead = 128

// Limits bound the ring buffer. All three are enforced, in this order: age,
// then rows, then bytes.
type Limits struct {
	MaxRequests int
	MaxBytes    int64
	MaxAge      time.Duration
}

// Store is the SQLite ring buffer.
//
// It keeps the row count and the byte total in memory so that trimming
// after every batch does not mean a SUM() over the table. DELETE ...
// RETURNING gives back exactly what was removed, so the totals stay exact
// without ever rescanning.
type Store struct {
	db *sql.DB

	mu    sync.Mutex
	lim   Limits
	rows  int
	bytes int64
}

// Open opens or creates the buffer at path and trims it to the limits.
//
// The trim on open is not belt and braces. It is the only thing that
// enforces max_age for a daemon that was shut down over a weekend: nothing
// else runs until traffic arrives.
func Open(path string, lim Limits) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	// One connection. Writes come from a single goroutine in batches and
	// reads are small indexed queries over a few thousand rows, so there is
	// nothing to gain from a pool and one less question about which
	// connection a PRAGMA applied to.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("creating schema in %s: %w", path, err)
	}

	s := &Store{db: db, lim: lim}
	row := db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM requests`)
	if err := row.Scan(&s.rows, &s.bytes); err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("reading buffer size from %s: %w", path, err)
	}
	if err := s.Trim(time.Now()); err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("trimming %s: %w", path, err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// SetLimits swaps the limits, for a config reload. The next trim applies
// them.
func (s *Store) SetLimits(lim Limits) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lim = lim
}

// Bytes reports the running byte total. Exported for tests and for the
// dashboard's status line.
func (s *Store) Bytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes
}

// Rows reports the running row count.
func (s *Store) Rows() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rows
}

// Insert writes a batch and trims. Each record's ID and SizeBytes are filled
// in on the way through.
func (s *Store) Insert(recs []*Record) error {
	if len(recs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	stmt, err := tx.Prepare(`
INSERT INTO requests (started_at, duration_us, domain, method, path, status,
                      proto, upgraded, req_bytes, resp_bytes, error,
                      req_headers, resp_headers, req_body, resp_body, size_bytes)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close() //nolint:errcheck

	var added int64
	for _, r := range recs {
		reqHdr := marshalHeaders(r.ReqHeaders)
		respHdr := marshalHeaders(r.RespHeaders)
		r.SizeBytes = int64(rowOverhead + len(reqHdr) + len(respHdr) +
			len(r.ReqBody) + len(r.RespBody) + len(r.Path) + len(r.Domain))

		res, err := stmt.Exec(
			r.StartedAt.UnixMicro(), r.Duration.Microseconds(), r.Domain,
			r.Method, r.Path, r.Status, r.Proto, boolToInt(r.Upgraded),
			r.ReqBytes, r.RespBytes, r.Error, reqHdr, respHdr,
			nilIfEmpty(r.ReqBody), nilIfEmpty(r.RespBody), r.SizeBytes)
		if err != nil {
			return err
		}
		if id, err := res.LastInsertId(); err == nil {
			r.ID = id
		}
		added += r.SizeBytes
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	s.mu.Lock()
	s.rows += len(recs)
	s.bytes += added
	s.mu.Unlock()

	return s.Trim(time.Now())
}

// Trim enforces all three limits. Age first, because it is the cheapest and
// the most likely to make the other two moot.
func (s *Store) Trim(now time.Time) error {
	s.mu.Lock()
	lim := s.lim
	s.mu.Unlock()

	if lim.MaxAge > 0 {
		cutoff := now.Add(-lim.MaxAge).UnixMicro()
		if err := s.deleteAndAccount(
			`DELETE FROM requests WHERE started_at < ? RETURNING size_bytes`, cutoff); err != nil {
			return err
		}
	}

	if lim.MaxRequests > 0 {
		if excess := s.Rows() - lim.MaxRequests; excess > 0 {
			if err := s.deleteAndAccount(
				`DELETE FROM requests WHERE id IN
				 (SELECT id FROM requests ORDER BY id ASC LIMIT ?) RETURNING size_bytes`,
				excess); err != nil {
				return err
			}
		}
	}

	if lim.MaxBytes > 0 {
		// One row at a time rather than computed: a running window sum in
		// SQL would be clever, but a fixed batch size can overshoot badly
		// when the byte cap is tight relative to the row cap — a batch of
		// 64 against a buffer that only ever holds a handful of rows before
		// the byte cap bites deletes the entire table in one go instead of
		// trimming it back under the limit. One row per iteration is always
		// exactly as much eviction as the cap demands, no more.
		for s.Bytes() > lim.MaxBytes && s.Rows() > 0 {
			if err := s.deleteAndAccount(
				`DELETE FROM requests WHERE id IN
				 (SELECT id FROM requests ORDER BY id ASC LIMIT 1) RETURNING size_bytes`); err != nil {
				return err
			}
		}
	}
	return nil
}

// deleteAndAccount runs a DELETE ... RETURNING size_bytes and subtracts
// exactly what it removed from the running totals.
func (s *Store) deleteAndAccount(query string, args ...any) error {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close() //nolint:errcheck

	var n int
	var freed int64
	for rows.Next() {
		var size int64
		if err := rows.Scan(&size); err != nil {
			return err
		}
		n++
		freed += size
	}
	if err := rows.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	s.rows -= n
	s.bytes -= freed
	if s.rows < 0 {
		s.rows = 0
	}
	if s.bytes < 0 {
		s.bytes = 0
	}
	s.mu.Unlock()
	return nil
}

// Clear empties the buffer.
func (s *Store) Clear() error {
	if _, err := s.db.Exec(`DELETE FROM requests`); err != nil {
		return err
	}
	s.mu.Lock()
	s.rows, s.bytes = 0, 0
	s.mu.Unlock()
	return nil
}

// Query filters a List. The zero value returns the newest rows unfiltered.
type Query struct {
	Domain string
	Method string
	Status string // "404" or "4xx"
	Q      string // path substring, case-insensitive
	Before int64  // return rows with a lower id; 0 means newest
	Limit  int    // default 200, capped at 500
}

const listColumns = `id, started_at, duration_us, domain, method, path, status,
                     proto, upgraded, req_bytes, resp_bytes, error,
                     req_headers, resp_headers, size_bytes`

// List returns matching records, newest first, without bodies. Bodies can be
// large and a list view never shows them; Get is for one record in full.
func (s *Store) List(q Query) ([]*Record, error) {
	var where []string
	var args []any

	if q.Domain != "" {
		where = append(where, "domain = ?")
		args = append(args, q.Domain)
	}
	if q.Method != "" {
		where = append(where, "method = ?")
		args = append(args, strings.ToUpper(q.Method))
	}
	if cond, arg, ok := statusCondition(q.Status); ok {
		where = append(where, cond)
		args = append(args, arg...)
	}
	if q.Q != "" {
		where = append(where, "path LIKE ? ESCAPE '\\'")
		args = append(args, "%"+escapeLike(q.Q)+"%")
	}
	if q.Before > 0 {
		where = append(where, "id < ?")
		args = append(args, q.Before)
	}

	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}

	sqlText := `SELECT ` + listColumns + ` FROM requests`
	if len(where) > 0 {
		sqlText += " WHERE " + strings.Join(where, " AND ")
	}
	sqlText += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.Query(sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := []*Record{}
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get returns one record with its bodies.
func (s *Store) Get(id int64) (*Record, error) {
	row := s.db.QueryRow(`SELECT `+listColumns+`, req_body, resp_body
	                      FROM requests WHERE id = ?`, id)
	var (
		r          Record
		startedAt  int64
		durationUS int64
		upgraded   int
		reqHdr     string
		respHdr    string
	)
	err := row.Scan(&r.ID, &startedAt, &durationUS, &r.Domain, &r.Method,
		&r.Path, &r.Status, &r.Proto, &upgraded, &r.ReqBytes, &r.RespBytes,
		&r.Error, &reqHdr, &respHdr, &r.SizeBytes, &r.ReqBody, &r.RespBody)
	if err != nil {
		return nil, err
	}
	r.StartedAt = time.UnixMicro(startedAt).UTC()
	r.Duration = time.Duration(durationUS) * time.Microsecond
	r.Upgraded = upgraded != 0
	r.ReqHeaders = unmarshalHeaders(reqHdr)
	r.RespHeaders = unmarshalHeaders(respHdr)
	return &r, nil
}

func scanRecord(rows *sql.Rows) (*Record, error) {
	var (
		r          Record
		startedAt  int64
		durationUS int64
		upgraded   int
		reqHdr     string
		respHdr    string
	)
	if err := rows.Scan(&r.ID, &startedAt, &durationUS, &r.Domain, &r.Method,
		&r.Path, &r.Status, &r.Proto, &upgraded, &r.ReqBytes, &r.RespBytes,
		&r.Error, &reqHdr, &respHdr, &r.SizeBytes); err != nil {
		return nil, err
	}
	r.StartedAt = time.UnixMicro(startedAt).UTC()
	r.Duration = time.Duration(durationUS) * time.Microsecond
	r.Upgraded = upgraded != 0
	r.ReqHeaders = unmarshalHeaders(reqHdr)
	r.RespHeaders = unmarshalHeaders(respHdr)
	return &r, nil
}

// statusCondition turns "404" or "4xx" into a WHERE fragment. Anything else
// is ignored rather than rejected: a filter the user cannot see is not worth
// a 400.
func statusCondition(s string) (string, []any, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return "", nil, false
	}
	if len(s) == 3 && strings.HasSuffix(s, "xx") {
		if d, err := strconv.Atoi(s[:1]); err == nil && d >= 1 && d <= 9 {
			return "status >= ? AND status < ?", []any{d * 100, (d + 1) * 100}, true
		}
		return "", nil, false
	}
	if n, err := strconv.Atoi(s); err == nil {
		return "status = ?", []any{n}, true
	}
	return "", nil, false
}

// escapeLike neutralises the wildcards in a user-supplied substring so that
// searching for "a_b" does not match "axb".
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func marshalHeaders(h map[string][]string) string {
	if len(h) == 0 {
		return "{}"
	}
	b, err := json.Marshal(h)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func unmarshalHeaders(s string) map[string][]string {
	if s == "" || s == "{}" {
		return map[string][]string{}
	}
	var out map[string][]string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return map[string][]string{}
	}
	return out
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nilIfEmpty(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
