package reconcile

import (
	"slices"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

// stubPrompter returns a scripted sequence of Select results, so a test can
// simulate "show diff, then keep" by queueing [2, 0]. Confirm is unused here.
type stubPrompter struct {
	selects []int
	calls   int
}

func (p *stubPrompter) next() int {
	if p.calls >= len(p.selects) {
		return -1
	}
	v := p.selects[p.calls]
	p.calls++
	return v
}

func (p *stubPrompter) Confirm(string) bool                  { return false }
func (p *stubPrompter) ConfirmWithDefault(string, bool) bool { return false }
func (p *stubPrompter) Select(string, []cmdutil.Option) int  { return p.next() }
func (p *stubPrompter) SelectWithGroups(string, map[string][]cmdutil.Option, []string) int {
	return -1
}
func (p *stubPrompter) Input(string, string) string                { return "" }
func (p *stubPrompter) MultiSelect(string, []cmdutil.Option) []int { return nil }

func newIO(terminal bool) *iostreams.IOStreams {
	io, _, _, _ := iostreams.Test()
	io.SetTerminal(terminal)
	return io
}

// baseRequest is a diverged (Equal:false) request with distinct rendered sides.
func baseRequest() Request {
	return Request{
		Subject: `allowlist for instance "dev"`,
		Equal:   false,
		Current: "onlydisk\n",
		Desired: "onlyyaml\n",
	}
}

func TestParseDecision(t *testing.T) {
	cases := map[string]Decision{
		"":        DecisionPrompt,
		"prompt":  DecisionPrompt,
		"keep":    DecisionKeep,
		"KEEP":    DecisionKeep,
		"replace": DecisionReplace,
	}
	for in, want := range cases {
		got, err := ParseDecision(in)
		if err != nil {
			t.Errorf("ParseDecision(%q) unexpected error: %v", in, err)
		}
		if got != want {
			t.Errorf("ParseDecision(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseDecision("bogus"); err == nil {
		t.Error("expected error for invalid policy")
	}
}

func TestResolve_EqualNoPrompt(t *testing.T) {
	req := baseRequest()
	req.Equal = true
	p := &stubPrompter{}
	got, err := Resolve(newIO(true), p, cmdutil.NewColorScheme(false), req)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if got != DecisionKeep {
		t.Errorf("equal inputs should return Keep, got %v", got)
	}
	if p.calls != 0 {
		t.Error("must not prompt when Current equals Desired")
	}
}

func TestResolve_ExplicitDecisionHonored(t *testing.T) {
	for _, d := range []Decision{DecisionKeep, DecisionReplace} {
		req := baseRequest()
		req.Decision = d
		p := &stubPrompter{}
		got, err := Resolve(newIO(true), p, cmdutil.NewColorScheme(false), req)
		if err != nil {
			t.Fatalf("Resolve error: %v", err)
		}
		if got != d {
			t.Errorf("explicit decision %v not honored, got %v", d, got)
		}
		if p.calls != 0 {
			t.Errorf("must not prompt when an explicit decision is set (%v)", d)
		}
	}
}

func TestResolve_InteractiveKeepAndReplace(t *testing.T) {
	// Select index 0 => Keep, 1 => Replace.
	tests := []struct {
		sel  int
		want Decision
	}{
		{0, DecisionKeep},
		{1, DecisionReplace},
	}
	for _, tt := range tests {
		p := &stubPrompter{selects: []int{tt.sel}}
		got, err := Resolve(newIO(true), p, cmdutil.NewColorScheme(false), baseRequest())
		if err != nil {
			t.Fatalf("Resolve error: %v", err)
		}
		if got != tt.want {
			t.Errorf("select %d => %v, want %v", tt.sel, got, tt.want)
		}
	}
}

func TestResolve_DiffThenReprompt(t *testing.T) {
	// Show diff (2), then Replace (1). The loop must re-prompt after the diff.
	p := &stubPrompter{selects: []int{2, 1}}
	got, err := Resolve(newIO(true), p, cmdutil.NewColorScheme(false), baseRequest())
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if got != DecisionReplace {
		t.Errorf("diff-then-replace should return Replace, got %v", got)
	}
	if p.calls != 2 {
		t.Errorf("expected 2 prompt rounds (diff then choice), got %d", p.calls)
	}
}

func TestResolve_NonInteractiveDefaultsToKeep(t *testing.T) {
	p := &stubPrompter{selects: []int{1}} // would say Replace if asked
	got, err := Resolve(newIO(false), p, cmdutil.NewColorScheme(false), baseRequest())
	if err != nil {
		t.Fatalf("non-interactive Resolve should not error, got %v", err)
	}
	if got != DecisionKeep {
		t.Errorf("non-interactive with no explicit decision should Keep, got %v", got)
	}
	if p.calls != 0 {
		t.Error("must not prompt in a non-interactive context")
	}
}

func TestResolve_CancelledSelectKeeps(t *testing.T) {
	// Select returns -1 (cancelled) => safe default Keep.
	p := &stubPrompter{selects: []int{-1}}
	got, err := Resolve(newIO(true), p, cmdutil.NewColorScheme(false), baseRequest())
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if got != DecisionKeep {
		t.Errorf("cancelled selection should Keep, got %v", got)
	}
}

func TestDifferCommand(t *testing.T) {
	t.Run("default is diff -u", func(t *testing.T) {
		t.Setenv("DIFFPROG", "")
		name, args := differCommand()
		if name != "diff" {
			t.Errorf("default differ = %q, want diff", name)
		}
		if len(args) == 0 || args[0] != "-u" {
			t.Errorf("default args = %v, want to start with -u", args)
		}
	})

	t.Run("honors DIFFPROG with args", func(t *testing.T) {
		t.Setenv("DIFFPROG", "git diff --no-index")
		name, args := differCommand()
		if name != "git" {
			t.Errorf("differ = %q, want git", name)
		}
		want := []string{"diff", "--no-index"}
		if !slices.Equal(args, want) {
			t.Errorf("args = %v, want %v", args, want)
		}
	})
}

func TestRunDiffer(t *testing.T) {
	// Force a deterministic differ available on the test host.
	t.Setenv("DIFFPROG", "diff -u")

	out, ok := runDiffer("alpha\ngone\n", "alpha\nadded\n")
	if !ok {
		t.Skip("diff binary not available on this host")
	}
	if !strings.Contains(out, "gone") || !strings.Contains(out, "added") {
		t.Errorf("diff output should mention both changed lines, got:\n%s", out)
	}
}

func TestRunDiffer_MissingBinary(t *testing.T) {
	t.Setenv("DIFFPROG", "this-differ-does-not-exist-abox")
	if _, ok := runDiffer("a\n", "b\n"); ok {
		t.Error("expected ok=false when the differ binary cannot run")
	}
}

func TestIndent(t *testing.T) {
	got := indent("a\n\nb\n")
	want := "  a\n\n  b"
	if got != want {
		t.Errorf("indent = %q, want %q", got, want)
	}
}
