package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeLines(t *testing.T, path string, n int, prefix string) {
	t.Helper()
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%s line %d\n", prefix, i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestTailLinesReportsTheOffsetItReadTo pins where the offset comes from: the
// size tailLines itself saw, not a second stat taken afterwards. printTail
// used to re-stat the file after reading it, and anything the daemon appended
// between the two measurements fell in a gap — printed by neither the tail
// nor the follow that resumed from the stat. The scenario where -f matters
// most, a crash-looping daemon appending continuously, is the one most likely
// to hit that window.
func TestTailLinesReportsTheOffsetItReadTo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	writeLines(t, path, 5, "o")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	_, offset, err := tailLines(path, 2)
	if err != nil {
		t.Fatal(err)
	}
	if offset != fi.Size() {
		t.Errorf("offset = %d, want %d — the end of what was actually read", offset, fi.Size())
	}
}

func TestTailLinesReturnsTheLastN(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	writeLines(t, path, 200, "x")

	got, _, err := tailLines(path, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 50 {
		t.Fatalf("got %d lines, want 50", len(got))
	}
	if got[0] != "x line 150" {
		t.Errorf("first line = %q, want %q (lines must come back oldest-first)", got[0], "x line 150")
	}
	if got[49] != "x line 199" {
		t.Errorf("last line = %q, want %q", got[49], "x line 199")
	}
}

// TestTailLinesAcrossChunkBoundary is the case the backwards read exists for
// and the one it can get wrong.
//
// Reading from the end in fixed-size chunks means the first chunk starts
// mid-line, so the earliest "line" in the buffer is a fragment. Returning it
// would put a truncated line at the top of every log view of a file larger
// than one chunk — plausible-looking output that silently lies about what the
// daemon wrote.
func TestTailLinesAcrossChunkBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	// Each line is ~50 bytes, so 4000 lines is well past tailChunk (64KiB)
	// and forces at least two backwards reads.
	writeLines(t, path, 4000, strings.Repeat("p", 32))

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() <= int64(tailChunk) {
		t.Fatalf("fixture is %d bytes, which does not exceed tailChunk (%d) — this test "+
			"would not exercise the boundary", fi.Size(), tailChunk)
	}

	got, _, err := tailLines(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 10 {
		t.Fatalf("got %d lines, want 10", len(got))
	}
	want := strings.Repeat("p", 32) + " line 3990"
	if got[0] != want {
		t.Errorf("first line = %q, want %q — a chunk boundary must not leave a "+
			"truncated line at the top", got[0], want)
	}
}

// TestTailLinesNeverReturnsAFragment forces the exact case the boundary
// handling exists for: a backwards read that lands mid-line and yields
// precisely as many lines as were asked for.
//
// That is where "stop once you have n lines" is wrong, because the oldest of
// those n is half a line. With the real 64KiB chunk this is unreachable — one
// read swallows thousands of lines — which is why tailChunk is a var: the
// previous version of this test passed with the boundary logic deliberately
// broken, and a test that cannot fail is not protecting anything.
func TestTailLinesNeverReturnsAFragment(t *testing.T) {
	orig := tailChunk
	tailChunk = 16
	t.Cleanup(func() { tailChunk = orig })

	// Ten 5-byte lines. Reading 16 bytes back from the end of 50 lands at
	// offset 34, one byte into a line, and yields exactly 4 lines — the
	// first of them a fragment.
	path := filepath.Join(t.TempDir(), "log")
	var b strings.Builder
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&b, "aaa%d\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	got, _, err := tailLines(path, 4)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"aaa6", "aaa7", "aaa8", "aaa9"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q — line %d is wrong; a chunk boundary must not "+
				"leave a truncated line in the result", got, want, i)
		}
	}
}

// TestTailLinesToleratesANonPositiveN: n comes straight from a user-typed
// flag, so nonsense values reach this function. n = -1 used to panic on the
// trim slice — a Go stack trace out of the command people run when something
// is already wrong.
func TestTailLinesToleratesANonPositiveN(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	writeLines(t, path, 3, "w")

	for _, n := range []int{0, -1, -50} {
		got, _, err := tailLines(path, n)
		if err != nil {
			t.Fatalf("tailLines(n=%d): %v", n, err)
		}
		if len(got) != 0 {
			t.Errorf("tailLines(n=%d) = %q, want no lines", n, got)
		}
	}
}

func TestTailLinesShorterThanRequested(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	writeLines(t, path, 3, "y")

	got, _, err := tailLines(path, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d lines, want all 3", len(got))
	}
	if got[0] != "y line 0" {
		t.Errorf("first line = %q, want the very first line of the file", got[0])
	}
}

// TestTailLinesKeepsAnUnterminatedFinalLine: a daemon killed mid-write leaves
// a line with no newline, and that partial line is often the most interesting
// thing in the file.
func TestTailLinesKeepsAnUnterminatedFinalLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, []byte("first\nsecond\nthird no newline"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _, err := tailLines(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != "third no newline" {
		t.Errorf("got %q, want the unterminated final line kept", got)
	}
}

// TestTailLinesEmptyFile: `daemon install` creates the log before anything
// writes to it, so this is a normal state, not an error.
func TestTailLinesEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got, _, err := tailLines(path, 10)
	if err != nil {
		t.Fatalf("an empty log is not an error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %q, want no lines", got)
	}
}

// TestPrintTailOffsetDoesNotRepeatOrSkip pins the handover between the tail
// and the follow. printTail reports where it stopped; if that offset were
// wrong, `-f` would either reprint the last lines or silently drop the next
// one — and a log viewer that drops a line is worse than one that shows none.
func TestPrintTailOffsetDoesNotRepeatOrSkip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	writeLines(t, path, 5, "z")

	var buf bytes.Buffer
	offset, err := printTail(path, 2, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "z line 3\nz line 4\n" {
		t.Errorf("tail output = %q", got)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("z line 5\n"); err != nil {
		t.Fatal(err)
	}
	f.Close() //nolint:errcheck

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var follow safeBuffer
	done := make(chan error, 1)
	go func() { done <- followFile(ctx, path, offset, &follow) }()

	waitFor(t, func() bool { return follow.String() == "z line 5\n" },
		"follow output = %q, want exactly the one appended line — no repeat, no skip",
		func() string { return follow.String() })

	cancel()
	<-done
}

// TestFollowFileRestartsAfterTruncation.
//
// A follow that keeps its offset across a truncation reads past the new end
// forever and prints nothing again — the failure mode is a viewer that looks
// alive and shows nothing, which is indistinguishable from a daemon that has
// gone quiet. Log rotation and `: > file` both produce this.
func TestFollowFileRestartsAfterTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, []byte("aaaa\nbbbb\ncccc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out safeBuffer
	done := make(chan error, 1)
	go func() { done <- followFile(ctx, path, fi.Size(), &out) }()

	// Truncate and write something shorter than the original.
	if err := os.WriteFile(path, []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	waitFor(t, func() bool { return strings.Contains(out.String(), "new") },
		"after truncation the follow printed %q, want the new content — keeping the "+
			"old offset makes it silent forever",
		func() string { return out.String() })

	cancel()
	<-done
}

// TestFollowFileWaitsForAFileThatDoesNotExistYet: `daemon install` then
// `daemon logs -f` is a normal sequence, and the log may not exist for a
// moment. Exiting there would read as the daemon having failed to start.
func TestFollowFileWaitsForAFileThatDoesNotExistYet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-yet")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out safeBuffer
	done := make(chan error, 1)
	go func() { done <- followFile(ctx, path, 0, &out) }()

	if err := os.WriteFile(path, []byte("appeared\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	waitFor(t, func() bool { return strings.Contains(out.String(), "appeared") },
		"follow printed %q, want the content once the file appeared",
		func() string { return out.String() })

	cancel()
	if err := <-done; err != nil {
		t.Errorf("a not-yet-created log must not be an error: %v", err)
	}
}

// safeBuffer is a bytes.Buffer usable from the follow goroutine and the test
// goroutine at once.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// waitFor polls cond until it holds or the deadline passes, then fails with
// msg formatted around actual(). Polling rather than a fixed sleep keeps the
// suite fast when the follow reacts promptly, which is the normal case.
func waitFor(t *testing.T, cond func() bool, msg string, actual func() string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf(msg, actual())
}
