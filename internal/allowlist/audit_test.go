package allowlist

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/logging"
)

// newAuditCapture builds a handler wired for audit capture, plus a func that
// returns the captured audit lines. It mirrors how the DNS/HTTP daemons
// construct the handler (Instance + Label set) so the emitted records carry the
// same attribution a real daemon would produce.
func newAuditCapture(t *testing.T, filter *Filter, server ModeServer, loader *Loader) (*AllowlistAPIHandler, func() string) {
	t.Helper()
	var buf bytes.Buffer
	restore := logging.SetAuditOutputForTest(&buf)
	t.Cleanup(restore)

	h := &AllowlistAPIHandler{
		Filter:   filter,
		Server:   server,
		Loader:   loader,
		Instance: "box1",
		Label:    "dns",
	}
	return h, buf.String
}

// countAudit returns the number of captured lines that mention the given action.
func countAudit(captured, action string) int {
	n := 0
	for line := range strings.SplitSeq(strings.TrimSpace(captured), "\n") {
		if line != "" && strings.Contains(line, action) {
			n++
		}
	}
	return n
}

func TestAudit_AddEmitsOnlyOnMutation(t *testing.T) {
	h, captured := newAuditCapture(t, NewFilter(), nil, nil)

	if _, err := h.Add("github.com"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	out := captured()
	if got := countAudit(out, logging.ActionAllowlistAdd); got != 1 {
		t.Fatalf("expected 1 add audit, got %d: %q", got, out)
	}
	// Attribution fields must be present so direct-socket records are usable.
	for _, want := range []string{"instance=box1", "filter=dns", "domain=github.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("audit line missing %q: %q", want, out)
		}
	}

	// A duplicate add is a no-op and must not emit a second record.
	if _, err := h.Add("github.com"); err != nil {
		t.Fatalf("Add duplicate: %v", err)
	}
	if got := countAudit(captured(), logging.ActionAllowlistAdd); got != 1 {
		t.Errorf("duplicate add should not audit; got %d records", got)
	}

	// An invalid domain is rejected before any mutation — no audit.
	if _, err := h.Add("invalid..domain"); err == nil {
		t.Fatal("expected error for invalid domain")
	}
	if got := countAudit(captured(), logging.ActionAllowlistAdd); got != 1 {
		t.Errorf("invalid add should not audit; got %d records", got)
	}
}

func TestAudit_RemoveEmitsOnlyOnMutation(t *testing.T) {
	filter := NewFilter()
	filter.Add("github.com")
	h, captured := newAuditCapture(t, filter, nil, nil)

	if _, err := h.Remove("github.com"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if got := countAudit(captured(), logging.ActionAllowlistRemove); got != 1 {
		t.Fatalf("expected 1 remove audit, got %d", got)
	}

	// Removing a domain that isn't present is a no-op error — no audit.
	if _, err := h.Remove("notthere.com"); err == nil {
		t.Fatal("expected NotFound error")
	}
	if got := countAudit(captured(), logging.ActionAllowlistRemove); got != 1 {
		t.Errorf("not-found remove should not audit; got %d records", got)
	}
}

func TestAudit_ReloadEmits(t *testing.T) {
	filter := NewFilter()
	dir := t.TempDir()
	conf := filepath.Join(dir, "allowlist.conf")
	if err := os.WriteFile(conf, []byte("github.com\nexample.org\n"), 0o600); err != nil {
		t.Fatalf("write conf: %v", err)
	}
	h, captured := newAuditCapture(t, filter, nil, NewLoader(conf, filter))

	if _, err := h.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	out := captured()
	if got := countAudit(out, logging.ActionAllowlistReload); got != 1 {
		t.Fatalf("expected 1 reload audit, got %d: %q", got, out)
	}
	if !strings.Contains(out, "domains=2") {
		t.Errorf("reload audit should record domain count; got %q", out)
	}
}

// SetMode audits on every valid set (active/passive), matching the prior CLI
// behavior; it does not compare against the current mode. The read path and
// invalid modes stay silent.
func TestAudit_SetModeEmitsOnSet(t *testing.T) {
	h, captured := newAuditCapture(t, NewFilter(), &mockModeServer{active: true}, nil)

	if _, err := h.SetMode("passive"); err != nil {
		t.Fatalf("SetMode passive: %v", err)
	}
	if _, err := h.SetMode("active"); err != nil {
		t.Fatalf("SetMode active: %v", err)
	}
	out := captured()
	if got := countAudit(out, logging.ActionModePassive); got != 1 {
		t.Errorf("expected 1 passive audit, got %d: %q", got, out)
	}
	if got := countAudit(out, logging.ActionModeActive); got != 1 {
		t.Errorf("expected 1 active audit, got %d: %q", got, out)
	}

	// The read path (empty mode) and invalid modes must not audit.
	before := len(strings.TrimSpace(captured()))
	if _, err := h.SetMode(""); err != nil {
		t.Fatalf("SetMode read: %v", err)
	}
	if _, err := h.SetMode("bogus"); err == nil {
		t.Fatal("expected error for invalid mode")
	}
	if len(strings.TrimSpace(captured())) != before {
		t.Errorf("read/invalid SetMode should not audit; output grew: %q", captured())
	}
}

func TestAudit_ProfileClearEmitsOnlyWithLogger(t *testing.T) {
	server := &mockModeServer{active: true}
	h, captured := newAuditCapture(t, NewFilter(), server, nil)

	// Clear with no logger is a no-op — no audit.
	if _, err := h.Profile("clear"); err != nil {
		t.Fatalf("Profile clear (no logger): %v", err)
	}
	if got := countAudit(captured(), logging.ActionProfileClear); got != 0 {
		t.Errorf("clear without logger should not audit; got %d", got)
	}

	logger, err := NewProfileLogger(filepath.Join(t.TempDir(), "profile.log"))
	if err != nil {
		t.Fatalf("NewProfileLogger: %v", err)
	}
	server.profileLogger = logger
	logger.LogDomain("test", "github.com")

	if _, err := h.Profile("clear"); err != nil {
		t.Fatalf("Profile clear: %v", err)
	}
	if got := countAudit(captured(), logging.ActionProfileClear); got != 1 {
		t.Errorf("expected 1 clear audit, got %d", got)
	}
}
