package cmdutil

import (
	"testing"

	"github.com/sandialabs/abox/internal/boxfile"
	"github.com/sandialabs/abox/internal/iostreams"
)

// stubPrompter answers Confirm with a fixed value and records the call.
type stubPrompter struct {
	confirm bool
	asked   bool
}

func (p *stubPrompter) Confirm(string) bool                                        { p.asked = true; return p.confirm }
func (p *stubPrompter) ConfirmWithDefault(string, bool) bool                       { return p.confirm }
func (p *stubPrompter) Select(string, []Option) int                                { return -1 }
func (p *stubPrompter) SelectWithGroups(string, map[string][]Option, []string) int { return -1 }
func (p *stubPrompter) Input(string, string) string                                { return "" }
func (p *stubPrompter) MultiSelect(string, []Option) []int                         { return nil }

func riskyBox() *boxfile.Boxfile {
	b := boxfile.DefaultBoxfile()
	b.HTTP.AllowPrivateTargets = []string{"127.0.0.0/8"} // security-relevant
	return b
}

func newIO(terminal bool) *iostreams.IOStreams {
	io, _, _, _ := iostreams.Test()
	io.SetTerminal(terminal)
	return io
}

func TestTrustBoxfile_EmptySummaryNoPrompt(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	cs := NewColorScheme(false)
	p := &stubPrompter{confirm: false}
	// Default boxfile has no security-relevant settings.
	if err := TrustBoxfile(newIO(true), p, cs, boxfile.DefaultBoxfile(), []byte("version: 1\n"), t.TempDir(), ""); err != nil {
		t.Fatalf("expected nil for empty summary, got %v", err)
	}
	if p.asked {
		t.Error("must not prompt when there is nothing security-relevant")
	}
}

func TestTrustBoxfile_NonInteractiveUntrustedFailsClosed(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	cs := NewColorScheme(false)
	err := TrustBoxfile(newIO(false), nil, cs, riskyBox(), []byte("version: 1\n"), t.TempDir(), "")
	if err == nil {
		t.Fatal("non-interactive untrusted risky boxfile must fail closed")
	}
}

func TestTrustBoxfile_InteractiveConfirmTrusts(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	cs := NewColorScheme(false)
	dir := t.TempDir()
	raw := []byte("version: 1\n")
	p := &stubPrompter{confirm: true}
	if err := TrustBoxfile(newIO(true), p, cs, riskyBox(), raw, dir, ""); err != nil {
		t.Fatalf("confirm should trust, got %v", err)
	}
	if !p.asked {
		t.Error("expected an interactive prompt")
	}
	// Second call is silent (already trusted at this fingerprint).
	p2 := &stubPrompter{confirm: false}
	if err := TrustBoxfile(newIO(true), p2, cs, riskyBox(), raw, dir, ""); err != nil {
		t.Fatalf("second call should be trusted silently, got %v", err)
	}
	if p2.asked {
		t.Error("must not re-prompt once trusted at the same fingerprint")
	}
}

func TestTrustBoxfile_InteractiveDeclineAborts(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	cs := NewColorScheme(false)
	p := &stubPrompter{confirm: false}
	err := TrustBoxfile(newIO(true), p, cs, riskyBox(), []byte("version: 1\n"), t.TempDir(), "")
	if err == nil {
		t.Fatal("declining the prompt must abort")
	}
	if !p.asked {
		t.Error("expected an interactive prompt before the decline")
	}
}

func TestTrustBoxfile_TrustTokenMatchTrustsNonInteractive(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	cs := NewColorScheme(false)
	dir := t.TempDir()
	raw := []byte("version: 1\n")
	box := riskyBox()
	fp := boxfile.TrustFingerprint(box, raw, dir)

	// Correct token trusts without a prompt, even non-interactively.
	if err := TrustBoxfile(newIO(false), nil, cs, box, raw, dir, fp); err != nil {
		t.Fatalf("matching trust token should succeed, got %v", err)
	}
	// A wrong token does not.
	t.Setenv("XDG_DATA_HOME", t.TempDir()) // fresh cache
	if err := TrustBoxfile(newIO(false), nil, cs, box, raw, dir, "wrong"); err == nil {
		t.Fatal("wrong trust token must not trust the boxfile")
	}
}
