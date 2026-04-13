// Package logutil provides log file utilities: tailing, following, and rotating.
package logutil

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

// TailLines reads and prints the last n lines of a file to w.
// If the file doesn't exist, it prints noFileMsg and returns nil.
// Uses a ring buffer to avoid loading entire file into memory.
func TailLines(w io.Writer, path string, n int, noFileMsg string) error {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		fmt.Fprintln(w, noFileMsg)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer f.Close()

	// Ring buffer to keep only last n lines (O(n) memory, not O(file size))
	ring := make([]string, n)
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ring[count%n] = scanner.Text()
		count++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read log file: %w", err)
	}

	// Print lines in order
	numLines := min(count, n)
	start := 0
	if count > n {
		start = count % n
	}
	for i := range numLines {
		fmt.Fprintln(w, ring[(start+i)%n])
	}

	return nil
}

// TailBuffer is an io.Writer that keeps the last n complete lines in a ring buffer.
// Call Flush to write the buffered lines to the underlying writer.
type TailBuffer struct {
	w     io.Writer
	n     int
	ring  []string
	count int
	buf   []byte // partial line accumulator
}

// NewTailBuffer creates a TailBuffer that retains the last n lines written to it.
func NewTailBuffer(w io.Writer, n int) *TailBuffer {
	return &TailBuffer{
		w:    w,
		n:    n,
		ring: make([]string, n),
	}
}

// Write buffers input and records each complete line in the ring buffer.
func (tb *TailBuffer) Write(p []byte) (int, error) {
	tb.buf = append(tb.buf, p...)
	for {
		idx := -1
		for i, b := range tb.buf {
			if b == '\n' {
				idx = i
				break
			}
		}
		if idx < 0 {
			break
		}
		line := string(tb.buf[:idx])
		tb.ring[tb.count%tb.n] = line
		tb.count++
		tb.buf = tb.buf[idx+1:]
	}
	return len(p), nil
}

// Flush writes the last n lines (in order) to the underlying writer, then
// writes any remaining partial line.
func (tb *TailBuffer) Flush() error {
	numLines := min(tb.count, tb.n)
	start := 0
	if tb.count > tb.n {
		start = tb.count % tb.n
	}
	for i := range numLines {
		if _, err := fmt.Fprintln(tb.w, tb.ring[(start+i)%tb.n]); err != nil {
			return err
		}
	}
	if len(tb.buf) > 0 {
		if _, err := tb.w.Write(tb.buf); err != nil {
			return err
		}
	}
	return nil
}

// ReadAll copies the entire contents of a file to w.
// If the file doesn't exist, it prints noFileMsg and returns nil.
func ReadAll(w io.Writer, path string, noFileMsg string) error {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		fmt.Fprintln(w, noFileMsg)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(w, f); err != nil {
		return fmt.Errorf("failed to read log file: %w", err)
	}
	return nil
}

// TailFollow streams new lines from a file using fsnotify (no CPU spinning).
// It handles file creation, writes, and log rotation/truncation gracefully.
func TailFollow(w io.Writer, path string, filterName string, noFileMsg string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	defer func() { _ = watcher.Close() }()

	// Watch directory (handles editor save patterns and file creation)
	dir := filepath.Dir(path)
	filename := filepath.Base(path)
	if err := watcher.Add(dir); err != nil {
		return fmt.Errorf("failed to watch directory: %w", err)
	}

	// Open file if it exists, otherwise wait for creation
	f, reader, err := openOrWait(w, path, noFileMsg)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "Following %s logs (Ctrl+C to stop)...\n", filterName)
	fmt.Fprintln(w)

	return followLoop(w, watcher, filename, path, f, reader)
}

// openOrWait opens the file at path for tailing. If the file does not exist,
// it prints a waiting message and returns nil for both file and reader.
func openOrWait(w io.Writer, path string, noFileMsg string) (*os.File, *bufio.Reader, error) {
	f, err := os.Open(path)
	switch {
	case os.IsNotExist(err):
		fmt.Fprintln(w, noFileMsg)
		fmt.Fprintln(w, "Waiting for log file to be created...")
		return nil, nil, nil
	case err != nil:
		return nil, nil, fmt.Errorf("failed to open log file: %w", err)
	default:
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			f.Close()
			return nil, nil, fmt.Errorf("failed to seek to end: %w", err)
		}
		return f, bufio.NewReader(f), nil
	}
}

// followLoop runs the main event loop for TailFollow, dispatching fsnotify events.
// It owns the file handle: f may be reassigned on rotation, and is closed on exit.
func followLoop(w io.Writer, watcher *fsnotify.Watcher, filename, path string, f *os.File, reader *bufio.Reader) error {
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if filepath.Base(event.Name) != filename {
				continue
			}
			var readErr error
			f, reader, readErr = handleFollowEvent(w, event, path, f, reader)
			if readErr != nil {
				return readErr
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			return fmt.Errorf("watcher error: %w", err)
		}
	}
}

// handleFollowEvent processes a single fsnotify event for TailFollow.
// Returns the (possibly updated) file and reader, and any fatal read error.
func handleFollowEvent(w io.Writer, event fsnotify.Event, path string, f *os.File, reader *bufio.Reader) (*os.File, *bufio.Reader, error) {
	switch {
	case event.Op&fsnotify.Create != 0:
		// File created or rotated - open fresh
		if f != nil {
			f.Close()
		}
		newF, err := os.Open(path)
		if err != nil {
			return nil, nil, nil //nolint:nilerr // file may not exist yet during rotation; caller retries
		}
		return newF, bufio.NewReader(newF), nil

	case event.Op&fsnotify.Write != 0:
		if f == nil || reader == nil {
			return f, reader, nil
		}
		if err := readNewLines(w, f, reader); err != nil {
			return f, reader, err
		}
	}
	return f, reader, nil
}

// readNewLines handles truncation detection and reads new lines from the file.
func readNewLines(w io.Writer, f *os.File, reader *bufio.Reader) error {
	info, err := f.Stat()
	if err == nil {
		currentPos, _ := f.Seek(0, io.SeekCurrent)
		if info.Size() < currentPos {
			_, _ = f.Seek(0, io.SeekStart)
			reader.Reset(f)
		}
	}
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to read log: %w", err)
		}
		fmt.Fprint(w, line)
	}
}
