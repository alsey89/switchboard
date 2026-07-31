package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"
)

// Reading the tail of a log, and following it.
//
// Implemented here rather than shelling out to tail(1) for two reasons: the
// daemon's log is the thing you read when something is already wrong, so it
// should not depend on another program being present and behaving as
// expected; and `tail -f` has no portable spelling, while this does.

// tailChunk is how much is read at a time when scanning backwards. Large
// enough that the common case (a few dozen short lines) is one read.
//
// A var so a test can shrink it. At 64KiB a single read swallows thousands of
// lines, which means the chunk-boundary handling below is never actually
// exercised by any plausible -n: a test written against the real value passed
// just as happily with the boundary logic broken.
var tailChunk = 64 * 1024

// tailLines returns the last n lines of the file at path, oldest first, and
// the offset of the end of what it read — the point a follow must resume from.
//
// The offset is the size tailLines itself saw, not something the caller can
// re-measure: a stat taken after the read may include bytes appended in
// between, and a follow resuming from that larger number silently skips them.
//
// It reads backwards from the end rather than reading the file and keeping
// the last n lines. The log is never rotated — a crash-looping service
// appends to it indefinitely — so "read it all, then discard almost all of
// it" is unbounded work for a bounded answer, and the day it matters most is
// the day the file is largest.
func tailLines(path string, n int) ([]string, int64, error) {
	// n is user-typed (`-n`); a negative value used to blow past the trim
	// slice below as a panic. The CLI rejects it first with an explanation —
	// this is the backstop that keeps the function total.
	if n < 0 {
		n = 0
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close() //nolint:errcheck

	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, 0, err
	}

	var (
		buf   []byte
		lines []string
		pos   = size
	)
	for pos > 0 {
		read := int64(tailChunk)
		if read > pos {
			read = pos
		}
		pos -= read

		chunk := make([]byte, read)
		if _, err := f.ReadAt(chunk, pos); err != nil && err != io.EOF {
			return nil, 0, err
		}
		buf = append(chunk, buf...)

		// Strictly greater than n, not >=. A chunk boundary lands mid-line,
		// so lines[0] is usually a fragment; having at least one line more
		// than asked for is what guarantees the fragment is discarded by the
		// slice below rather than returned as though it were a whole line.
		if lines = splitLines(buf); len(lines) > n || pos == 0 {
			break
		}
	}

	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, size, nil
}

// splitLines splits on \n and drops a single trailing empty element, so a
// file ending in a newline does not report a blank final line.
func splitLines(b []byte) []string {
	var (
		lines []string
		start int
	)
	for i, c := range b {
		if c == '\n' {
			lines = append(lines, string(b[start:i]))
			start = i + 1
		}
	}
	if start < len(b) {
		lines = append(lines, string(b[start:]))
	}
	return lines
}

// followPoll is how often followFile checks for new output. A var so the
// test does not wait on it.
var followPoll = 250 * time.Millisecond

// followFile streams appended bytes to out until ctx is cancelled.
//
// It starts from `from` (the offset the caller has already printed up to) and
// handles two things the naive version gets wrong. A file that has *shrunk*
// was truncated or replaced — keep reading from the old offset and you emit
// nothing ever again, so it restarts from the beginning. And a file that does
// not exist yet is not an error: `daemon install` creates the service before
// the daemon has written anything, and a follow that exits there would look
// like the daemon had failed.
func followFile(ctx context.Context, path string, from int64, out io.Writer) error {
	offset := from
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(followPoll):
		}

		fi, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue // not written to yet; keep waiting
			}
			return err
		}
		switch {
		case fi.Size() == offset:
			continue
		case fi.Size() < offset:
			// Truncated or replaced under us.
			offset = 0
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close() //nolint:errcheck
			return err
		}
		n, err := io.Copy(out, f)
		f.Close() //nolint:errcheck
		if err != nil {
			return err
		}
		offset += n
	}
}

// printTail writes the last n lines of path to out and returns the offset it
// read up to, so a follow can continue from exactly there without repeating
// or skipping a line. The offset comes from tailLines itself — see its doc
// for why it must not be measured again here.
func printTail(path string, n int, out io.Writer) (int64, error) {
	lines, offset, err := tailLines(path, n)
	if err != nil {
		return 0, err
	}
	for _, l := range lines {
		fmt.Fprintln(out, l)
	}
	return offset, nil
}
