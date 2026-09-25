// Package reconcile implements an apt/dpkg-style conffile-conflict resolution
// policy: when a desired state (e.g. declared in abox.yaml) diverges from an
// on-disk state that may have been modified locally, decide whether to keep the
// local version, replace it with the desired one, or show the user a diff and
// ask again — with a safe, fail-closed default for non-interactive callers.
//
// The package is deliberately file-agnostic: it compares two opaque values via
// caller-supplied Equal/Diff callbacks and returns the Decision to apply. The
// caller owns all I/O, so each consumer keeps its own file-safety invariants.
// This is the shared primitive behind `abox up`'s allowlist reconcile; other
// declarative-vs-persisted syncs can reuse it.
package reconcile

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

// Decision is the caller's choice (or the resolved non-interactive default) for
// how to handle a detected divergence.
type Decision int

const (
	// DecisionPrompt means: ask interactively if possible, else fall back to the
	// safe default (Keep). It is the zero value, so a caller that sets nothing
	// gets safe behavior automatically.
	DecisionPrompt Decision = iota
	// DecisionKeep keeps the on-disk version unchanged.
	DecisionKeep
	// DecisionReplace overwrites the on-disk version with the desired one.
	DecisionReplace
)

// ParseDecision maps a flag/env string to a Decision. An empty string yields
// DecisionPrompt (the default). Unknown values are an error.
func ParseDecision(s string) (Decision, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return DecisionPrompt, nil
	case "prompt", "ask":
		return DecisionPrompt, nil
	case "keep", "confold", "old":
		return DecisionKeep, nil
	case "replace", "confnew", "new":
		return DecisionReplace, nil
	default:
		return DecisionPrompt, fmt.Errorf("invalid policy %q (want keep, replace, or prompt)", s)
	}
}

// Request describes one reconcile check. The caller computes equality and
// renders the two versions to text itself (with its own concrete types), so the
// primitive stays content-agnostic without opaque values or callbacks.
type Request struct {
	// Subject names what is being reconciled, for prompt/advisory text
	// (e.g. `allowlist for instance "dev"`).
	Subject string

	// Equal reports whether the on-disk and desired states are the same in the
	// sense that matters to the caller (e.g. the same set of domains, ignoring
	// comments and ordering). When true, Resolve returns DecisionKeep without
	// prompting.
	Equal bool

	// Current and Desired are the on-disk and desired versions rendered to text
	// (one entry per line). They are used only for the interactive "show diff"
	// view, which diffs them with $DIFFPROG (falling back to `diff -u`). Leave
	// both empty to omit the diff option from the menu.
	Current, Desired string

	// Decision is the caller's pre-selected policy (from a flag/env). The zero
	// value DecisionPrompt triggers interactive-or-default behavior.
	Decision Decision
}

// Resolve returns the Decision to apply for req. It never mutates anything —
// the caller applies the result (Keep is a no-op; Replace means the caller
// writes the desired version).
//
// The signature mirrors cmdutil.TrustBoxfile: discrete io/prompter/cs params.
// Behavior:
//   - req.Equal => DecisionKeep, no prompt.
//   - req.Decision is Keep or Replace (explicit) => honored without prompting.
//   - Interactive TTY with a Prompter => Keep / Replace / (optional) Diff loop.
//   - Non-interactive with no explicit decision => DecisionKeep (fail-closed:
//     never silently clobber local edits). Unlike the trust gate this is a
//     success, not an error — the caller decides whether to print an advisory.
func Resolve(io *iostreams.IOStreams, prompter cmdutil.Prompter, cs *cmdutil.ColorScheme, req Request) (Decision, error) {
	if req.Equal {
		return DecisionKeep, nil
	}

	// An explicit Keep/Replace (from a flag/env) is honored without prompting.
	if req.Decision == DecisionKeep || req.Decision == DecisionReplace {
		return req.Decision, nil
	}

	// DecisionPrompt (including the zero value): interactive if we can, otherwise
	// the safe fail-closed default.
	if io.IsTerminal() && prompter != nil {
		return promptLoop(io, prompter, req), nil
	}
	return DecisionKeep, nil
}

// promptLoop drives the keep/replace/(diff) menu, re-prompting after a diff.
func promptLoop(io *iostreams.IOStreams, prompter cmdutil.Prompter, req Request) Decision {
	hasDiff := req.Current != "" || req.Desired != ""
	options := []cmdutil.Option{
		{Label: "Keep", Description: "keep the current on-disk version"},
		{Label: "Replace", Description: "overwrite with the version from abox.yaml"},
	}
	if hasDiff {
		options = append(options, cmdutil.Option{Label: "Show diff", Description: "show the difference, then ask again"})
	}

	prompt := req.Subject + " differs from abox.yaml. What would you like to do?"
	for {
		switch prompter.Select(prompt, options) {
		case 0:
			return DecisionKeep
		case 1:
			return DecisionReplace
		case 2:
			if hasDiff {
				showDiff(io, req.Current, req.Desired)
				continue
			}
			return DecisionKeep
		default:
			// Cancelled / invalid selection: keep is the safe default.
			return DecisionKeep
		}
	}
}

// showDiff writes the two rendered versions to temp files and runs a differ,
// honoring $DIFFPROG (the pacman/pacdiff convention) and falling back to
// `diff -u`. Output goes to ErrOut. A differ that can't run (or produces
// nothing) degrades to printing the two versions inline so the user still sees
// something.
func showDiff(io *iostreams.IOStreams, current, desired string) {
	fmt.Fprintln(io.ErrOut)
	out, ok := runDiffer(current, desired)
	if ok && strings.TrimSpace(out) != "" {
		fmt.Fprint(io.ErrOut, out)
		if !strings.HasSuffix(out, "\n") {
			fmt.Fprintln(io.ErrOut)
		}
		fmt.Fprintln(io.ErrOut)
		return
	}
	// Fallback: show both versions directly.
	fmt.Fprintln(io.ErrOut, "current (on disk):")
	fmt.Fprintln(io.ErrOut, indent(current))
	fmt.Fprintln(io.ErrOut, "desired (abox.yaml):")
	fmt.Fprintln(io.ErrOut, indent(desired))
}

// runDiffer writes current/desired to temp files and runs the differ. It
// returns the combined output and whether the differ ran (a non-zero exit, as
// `diff` returns when files differ, still counts as "ran").
func runDiffer(current, desired string) (string, bool) {
	dir, err := os.MkdirTemp("", "abox-reconcile-")
	if err != nil {
		return "", false
	}
	defer func() { _ = os.RemoveAll(dir) }()

	curPath := filepath.Join(dir, "current")
	desPath := filepath.Join(dir, "desired")
	if err := os.WriteFile(curPath, []byte(current), 0o600); err != nil {
		return "", false
	}
	if err := os.WriteFile(desPath, []byte(desired), 0o600); err != nil {
		return "", false
	}

	name, args := differCommand()
	args = append(args, curPath, desPath)
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		if _, ok := errors.AsType[*exec.ExitError](err); !ok {
			// The differ itself couldn't run (missing binary, etc.).
			return "", false
		}
	}
	return string(out), true
}

// defaultDiffProg is the differ used when $DIFFPROG is unset.
const defaultDiffProg = "diff"

// differCommand resolves the differ program and its leading arguments from
// $DIFFPROG, falling back to `diff -u --label current --label desired`.
func differCommand() (string, []string) {
	if prog := strings.TrimSpace(os.Getenv("DIFFPROG")); prog != "" {
		if fields := strings.Fields(prog); len(fields) > 0 {
			return fields[0], fields[1:]
		}
	}
	return defaultDiffProg, []string{"-u", "--label", "current", "--label", "desired"}
}

// indent prefixes each non-empty line of s with two spaces for readable inline
// fallback output.
func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = "  " + l
		}
	}
	return strings.Join(lines, "\n")
}
