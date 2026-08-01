package inspect

import (
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// current is the process-wide recorder the Caddy handler talks to.
//
// A Caddy module cannot be handed a Go pointer through JSON config, but the
// stronger reason for a package-level pointer is lifecycle: every
// `switchboard add` reloads the Caddy config and re-provisions every handler
// instance, while the recorder owns a SQLite handle, an in-flight batch and
// a set of live subscribers. All of that has to outlive a config reload, so
// it cannot be owned by a module Caddy is free to throw away.
//
// nil means "not capturing", and every caller treats it as pass-through.
var current atomic.Pointer[Recorder]

// Current returns the active recorder, or nil when capture is off.
func Current() *Recorder { return current.Load() }

// SetCurrent installs the active recorder. The daemon calls this before it
// loads the proxy config, and clears it on shutdown.
func SetCurrent(r *Recorder) { current.Store(r) }

// Options configure a Recorder. The zero value is usable: it means bodies
// off, default buffer sizes and a real one hour trim ticker.
type Options struct {
	Bodies       bool
	MaxBodyBytes int

	Buffer int           // channel depth, default 1024
	Batch  int           // max records per insert, default 64
	Flush  time.Duration // max wait before writing a partial batch, default 100ms

	// TrimTick replaces the internal one hour ticker. Tests inject a channel
	// so they do not have to wait an hour.
	TrimTick <-chan time.Time

	Log *slog.Logger
}

// Recorder is the bus between the request path and the store.
//
// Submit is called from Caddy's request goroutines and never blocks. One
// drain goroutine owns all the writing and all the fan-out.
type Recorder struct {
	ch    chan *Record
	store *Store
	log   *slog.Logger

	dropped atomic.Int64
	bodies  atomic.Bool
	maxBody atomic.Int64

	mu     sync.Mutex
	subs   map[int64]chan *Record
	nextID int64
	closed bool // set once the drain goroutine has torn down subscribers

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// New starts a recorder writing into store.
func New(store *Store, opts Options) *Recorder {
	if opts.Buffer <= 0 {
		opts.Buffer = 1024
	}
	if opts.Batch <= 0 {
		opts.Batch = 64
	}
	if opts.Flush <= 0 {
		opts.Flush = 100 * time.Millisecond
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}

	r := &Recorder{
		ch:    make(chan *Record, opts.Buffer),
		store: store,
		log:   opts.Log,
		subs:  map[int64]chan *Record{},
		done:  make(chan struct{}),
	}
	r.bodies.Store(opts.Bodies)
	r.maxBody.Store(int64(opts.MaxBodyBytes))

	tick := opts.TrimTick
	var ticker *time.Ticker
	if tick == nil {
		ticker = time.NewTicker(time.Hour)
		tick = ticker.C
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		if ticker != nil {
			defer ticker.Stop()
		}
		r.drain(opts.Batch, opts.Flush, tick)
	}()
	return r
}

// Submit hands a record to the recorder. It never blocks: a full buffer
// drops the record and counts it. Losing a row is a nuisance. Adding
// latency to somebody's dev request is not acceptable.
func (r *Recorder) Submit(rec *Record) {
	select {
	case r.ch <- rec:
	default:
		r.dropped.Add(1)
	}
}

// Dropped reports how many records were lost: either dropped from a full
// buffer, or lost because a batch failed to write to the store. Either way
// they never reached the store, which is the one thing an operator querying
// this number needs to know — not which of the two happened.
func (r *Recorder) Dropped() int64 { return r.dropped.Load() }

// Store returns the underlying buffer, for history queries.
func (r *Recorder) Store() *Store { return r.store }

// Bodies reports whether body capture is on.
func (r *Recorder) Bodies() bool { return r.bodies.Load() }

// MaxBodyBytes is the per-body capture cap.
func (r *Recorder) MaxBodyBytes() int { return int(r.maxBody.Load()) }

// SetOptions updates the settings a config reload can change.
func (r *Recorder) SetOptions(bodies bool, maxBody int) {
	r.bodies.Store(bodies)
	r.maxBody.Store(int64(maxBody))
}

// Subscribe returns a channel of newly stored records and a function to stop
// receiving. The channel is closed when the subscription ends, whether the
// caller cancelled it or the recorder dropped a slow reader.
//
// A subscription requested after the drain goroutine has already shut down
// gets a channel that is already closed and a cancel that does nothing:
// there is nobody left to add it to, and a caller ranging over the channel
// (an SSE handler, in particular) must see it end rather than hang forever
// waiting for a record that will never come.
func (r *Recorder) Subscribe() (<-chan *Record, func()) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		ch := make(chan *Record)
		close(ch)
		return ch, func() {}
	}
	ch := make(chan *Record, 256)
	r.nextID++
	id := r.nextID
	r.subs[id] = ch
	r.mu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			r.mu.Lock()
			if c, ok := r.subs[id]; ok {
				delete(r.subs, id)
				close(c)
			}
			r.mu.Unlock()
		})
	}
}

// publish fans a batch out to subscribers. A subscriber that cannot keep up
// is dropped rather than slowed down: its channel closes, and because the
// feed is SSE the browser reconnects on its own and backfills from the
// store. Nothing here is allowed to block the drain loop.
func (r *Recorder) publish(recs []*Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, ch := range r.subs {
		for _, rec := range recs {
			select {
			case ch <- rec:
			default:
				delete(r.subs, id)
				close(ch)
				goto next
			}
		}
	next:
	}
}

// closeSubscribers tears down every live subscription and marks the
// recorder closed so a later Subscribe call knows not to add a channel that
// nothing will ever close. It runs exactly once, from drain's deferred
// cleanup, so it fires whether drain returns normally or panics — a
// subscriber must never be left holding a channel nobody is going to close.
func (r *Recorder) closeSubscribers() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	for id, ch := range r.subs {
		delete(r.subs, id)
		close(ch)
	}
}

// drain owns every write. It batches to keep the transaction count down and
// flushes on a timer so a single request does not sit unwritten.
func (r *Recorder) drain(batchSize int, flush time.Duration, tick <-chan time.Time) {
	defer func() {
		// A panic here would otherwise leave every subscriber channel open
		// forever: an SSE handler ranging over one would hang rather than
		// see the recorder die. closeSubscribers must run on every exit
		// path, panic or not, which is why it lives in this defer rather
		// than only at the bottom of the shutdown case below.
		if p := recover(); p != nil {
			r.log.Error("inspector recorder stopped after a panic", "panic", p)
		}
		r.closeSubscribers()
	}()

	batch := make([]*Record, 0, batchSize)
	timer := time.NewTimer(flush)
	defer timer.Stop()

	write := func() {
		if len(batch) == 0 {
			return
		}
		err := r.store.Insert(batch)
		switch {
		case err == nil:
			r.publish(batch)
		case errors.Is(err, ErrTrimAfterInsert):
			// The batch itself committed before Trim ran; only the
			// ring-buffer cleanup after it failed. The rows are really in
			// the store, so subscribers can still be told about them —
			// treating this the same as a real write failure would hide a
			// live update for rows that are not actually missing.
			r.log.Warn("inspector trim failed after a successful insert", "err", err)
			r.publish(batch)
		default:
			// Nothing committed. This has to be as visible as a full-buffer
			// drop, or Dropped() understates how much was actually lost.
			r.log.Warn("inspector could not write a batch", "err", err, "records", len(batch))
			r.dropped.Add(int64(len(batch)))
		}
		batch = batch[:0]
	}

	for {
		select {
		case rec := <-r.ch:
			batch = append(batch, rec)
			if len(batch) >= batchSize {
				write()
			}

		case <-timer.C:
			write()
			timer.Reset(flush)

		case now := <-tick:
			// Trim on a clock, not only on traffic. A daemon that stays up
			// for a week with three quiet days in the middle would otherwise
			// hold rows well past max_age.
			if err := r.store.Trim(now); err != nil {
				r.log.Warn("inspector could not trim", "err", err)
			}

		case <-r.done:
			// Drain what is already queued, then stop. Subscriber teardown
			// happens in the deferred cleanup above, not here, so it also
			// runs if something above panics instead of reaching this case.
			for {
				select {
				case rec := <-r.ch:
					batch = append(batch, rec)
					continue
				default:
				}
				break
			}
			write()
			return
		}
	}
}

// Close stops the drain goroutine, flushes what is queued and closes the
// store.
func (r *Recorder) Close() error {
	r.closeOnce.Do(func() { close(r.done) })
	r.wg.Wait()
	return r.store.Close()
}
