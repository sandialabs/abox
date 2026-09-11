//go:build darwin

package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"
)

// auditSentinel prefixes every macOS unified-log audit line so events can be
// filtered back out with:
//
//	log show --predicate 'process == "logger" && eventMessage BEGINSWITH "abox"'
//
// The `logger -t` tag is not a queryable unified-log field, so the sentinel in the
// message body is what makes read-back reliable.
const auditSentinel = "abox"

// On macOS, audit events go to the system unified log via /usr/bin/logger rather
// than a file. Routing through the OS-owned log keeps events out of a
// user-writable file under $HOME that an untrusted agent could simply edit or
// remove, and consolidates them where an operator already looks (`log show`).
//
// DURABILITY LIMITATION: this is NOT yet the tamper-resistant, guaranteed-durable
// equivalent of the Linux root-owned syslog file. The `logger(1)` CLI is
// os_log-backed and its messages land at os_log INFO level (which is exactly why
// the read-back command below needs `--info`). By Apple's default logging policy
// INFO-level entries are collected to the in-memory ring buffer and are NOT
// persisted to the on-disk store (/var/db/diagnostics) unless persistence has been
// explicitly enabled (e.g. `sudo log config --mode persist:info`), which abox does
// not do. So under load or across a reboot these events can age out of the buffer
// and a later `log show` may return nothing. A fully durable, non-root-erasable
// trail requires a different sink (e.g. a root-owned append-only file written via
// the privilege helper, mirroring Linux) — see TODO(audit-durability); the current
// sink is best-effort until then. Do not rely on it for guaranteed post-incident
// review.
//
// CGO is disabled, so the os_log(3) C API is unavailable; /usr/bin/logger is the
// CGO-free path to the unified log. We keep a single long-lived logger child per
// abox process and feed it one line per record over stdin (logger emits one entry
// per line as it reads), which avoids an exec per audit event for high-frequency
// callers (e.g. httpfilter blocks). The child runs at -p user.notice (the intended
// severity), though the CLI still surfaces the entries at INFO. Read back with:
//
//	log show --predicate 'process == "logger" && eventMessage BEGINSWITH "abox"' --info

// loggerPath is the absolute path to the unified-log writer. Absolute (not via
// PATH) as a defense against PATH manipulation, matching the helper's /sbin/pfctl.
const loggerPath = "/usr/bin/logger"

// newLoggerCmd builds the long-lived logger child. A package var so tests can swap
// in a fake capturing stdin (mirrors qemuimg.runCmd). Empty env: logger is invoked
// by absolute path and needs no PATH/locale, matching the helper_darwin convention.
var newLoggerCmd = func() *exec.Cmd {
	cmd := exec.Command(loggerPath, "-p", "user.notice", "-t", "abox")
	cmd.Env = []string{}
	return cmd
}

// loggerPipe owns the single long-lived logger child for this process. One per
// abox process, shared by every handler clone (slog clones handlers freely via
// WithAttrs/WithGroup; they must not each spawn a child). All access is guarded by
// mu; the globals below are guarded separately by auditMu.
type loggerPipe struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	dead     bool      // once true, all writes discard (child gone or sink closed)
	warnOnce sync.Once // warn at most once when a write first fails
}

// auditPipe/auditInited mirror the Linux/other sink lifecycle. auditMu guards them:
// a plain sync.Once could not be reset for re-open without a data race against a
// concurrent open/close (e.g. under `go test -race`).
var (
	auditMu     sync.Mutex
	auditPipe   *loggerPipe
	auditInited bool
)

// startLoggerChild launches a logger child and returns it with its stdin pipe.
func startLoggerChild() (*exec.Cmd, io.WriteCloser, error) {
	cmd := newLoggerCmd()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return cmd, stdin, nil
}

// write emits one pre-framed line (including its trailing newline) to the logger
// child. Best-effort: a dead child never crashes abox. On failure it warns once,
// then attempts one respawn+retry for this failure. A successful retry leaves the
// sink live so a later, independent failure can respawn again; only if the fresh
// child also rejects the line does it give up (fail closed) and make the loss
// visible — silent discard would undermine the tamper-resistance this sink exists
// for. Must not return an error — multiHandler would propagate it.
func (p *loggerPipe) write(b []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.dead || p.stdin == nil {
		return
	}
	if _, err := p.stdin.Write(b); err == nil {
		return
	}
	p.warnOnce.Do(func() {
		fmt.Fprintln(os.Stderr, "abox: warning: audit logger write failed; respawning")
	})
	if !p.respawnLocked() {
		p.markDeadLocked()
		return
	}
	if _, err := p.stdin.Write(b); err != nil {
		p.markDeadLocked()
	}
}

// markDeadLocked disables the sink and makes the audit gap visible (once). Caller
// holds p.mu.
func (p *loggerPipe) markDeadLocked() {
	if p.dead {
		return
	}
	p.dead = true
	fmt.Fprintln(os.Stderr, "abox: warning: audit logging disabled: unified-log writer unavailable")
}

// respawnLocked closes the old child's stdin and starts a fresh one, reaping the
// old child asynchronously so a wedged logger can never block p.mu (and thus every
// other audit write and shutdown). Caller holds p.mu.
func (p *loggerPipe) respawnLocked() bool {
	if p.stdin != nil {
		_ = p.stdin.Close()
	}
	if old := p.cmd; old != nil {
		go func() { _ = old.Wait() }()
	}
	cmd, stdin, err := startLoggerChild()
	if err != nil {
		return false
	}
	p.cmd, p.stdin = cmd, stdin
	return true
}

// initAuditSink starts the logger child. Idempotent and race-safe; only the first
// call after each close acts. Leaves auditPipe nil (→ discard fallback) if logger
// is missing or fails to start.
func initAuditSink() {
	auditMu.Lock()
	defer auditMu.Unlock()
	if auditInited {
		return
	}
	auditInited = true

	if _, err := os.Stat(loggerPath); err != nil {
		fmt.Fprintf(os.Stderr, "abox: warning: audit logging unavailable: %s: %v\n", loggerPath, err)
		return
	}
	cmd, stdin, err := startLoggerChild()
	if err != nil {
		fmt.Fprintf(os.Stderr, "abox: warning: cannot start audit logger: %v\n", err)
		return
	}
	auditPipe = &loggerPipe{cmd: cmd, stdin: stdin}
}

// closeAuditSink drains and stops the logger child. Called by CloseLogFile. It
// marks the pipe dead (so any late handler clone still holding it discards instead
// of writing to a Wait()-ed child — the key -race invariant), closes stdin so
// logger drains its buffered lines and exits, then waits with a bounded timeout so
// a wedged logger cannot hang shutdown.
func closeAuditSink() {
	auditMu.Lock()
	p := auditPipe
	auditPipe = nil
	auditInited = false
	auditMu.Unlock()
	if p == nil {
		return
	}

	p.mu.Lock()
	p.dead = true
	stdin := p.stdin
	p.stdin = nil
	cmd := p.cmd
	p.mu.Unlock()

	if stdin != nil {
		_ = stdin.Close()
	}
	if cmd != nil {
		waitWithTimeout(cmd, 2*time.Second)
	}
}

// waitWithTimeout waits for cmd, killing it if it does not exit within d. It does
// not block on the reaper after Kill: if the child cannot be reaped, waiting would
// hang shutdown — the goroutine simply exits if/when the child dies.
func waitWithTimeout(cmd *exec.Cmd, d time.Duration) {
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		_ = cmd.Process.Kill()
	}
}

// newAuditHandler returns the macOS unified-log slog.Handler, or nil if the logger
// child could not be started (→ discardHandler fallback in logging.go).
//
// It self-initializes the sink via the idempotent initAuditSink(), mirroring the
// Linux/other newAuditHandler() (which self-init via newSyslogHandler). This
// guarantees a non-nil handler whenever the logger is available, even if the
// caller reaches newAuditHandler before Init — without it, a caller (or a test)
// that has not run initAuditSink first would silently get a nil handler and drop
// audit events. initAuditSink takes auditMu itself, so it must run before the
// lock below (not nested).
func newAuditHandler() slog.Handler {
	initAuditSink()
	auditMu.Lock()
	p := auditPipe
	auditMu.Unlock()
	if p == nil {
		return nil
	}
	return &loggerAuditHandler{pipe: p}
}

// AuditLogPath reports the macOS audit destination. Symmetric with Linux's
// "(syslog)"; the read-back command lives in AuditLogHint.
func AuditLogPath() string {
	return "(unified log)"
}

// AuditLogHint returns how to read abox audit events from the macOS unified log.
// --info is required: the logger CLI's entries surface at os_log INFO level and
// are hidden without it. The "abox" sentinel (see auditSentinel) makes BEGINSWITH
// reliable — the logger -t tag is not a queryable unified-log field. Note: these
// INFO-level entries live in the in-memory buffer and may age out, so `log show`
// can miss older events (see the durability limitation documented above);
// `log stream` reliably captures events from the moment it is started.
func AuditLogHint() string {
	return `log show --predicate 'process == "logger" && eventMessage BEGINSWITH "abox"' --info   (recent, best-effort)
  log stream --predicate 'process == "logger" && eventMessage BEGINSWITH "abox"' --info   (live)`
}

// loggerAuditHandler is a slog.Handler that writes one key=value line per record
// to the shared logger child. INFO level and above only; flat key/value.
type loggerAuditHandler struct {
	pipe  *loggerPipe
	attrs []slog.Attr
	group string
}

func (h *loggerAuditHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo
}

func (h *loggerAuditHandler) Handle(_ context.Context, r slog.Record) error {
	// formatAuditLine returns a CR/LF-free body; the sentinel and RFC3339 timestamp
	// are newline-free by construction, so the line has exactly one newline: ours.
	line := auditSentinel + " " + r.Time.UTC().Format(time.RFC3339) + " " + formatAuditLine(r, h.attrs, h.group)
	h.pipe.write([]byte(line + "\n"))
	return nil
}

func (h *loggerAuditHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	copy(newAttrs[len(h.attrs):], attrs)
	return &loggerAuditHandler{pipe: h.pipe, attrs: newAttrs, group: h.group}
}

func (h *loggerAuditHandler) WithGroup(name string) slog.Handler {
	g := name
	if h.group != "" {
		g = h.group + "." + name
	}
	return &loggerAuditHandler{pipe: h.pipe, attrs: h.attrs, group: g}
}

// auditHandlerInDefaultLogger is false on macOS: the audit sink carries audit
// events only, never general operational logs.
const auditHandlerInDefaultLogger = false
