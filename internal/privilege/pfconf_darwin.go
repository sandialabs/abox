//go:build darwin

package privilege

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// PF anchor reference management for /etc/pf.conf.
//
// pfctl loads per-instance rules into the abox/<name> sub-anchor namespace,
// but the kernel only descends into those anchors during evaluation if the
// main ruleset references them. macOS's default /etc/pf.conf doesn't, so we
// add two lines: one to the translation section, one to the filter section.
//
// PF requires strict section ordering (options → normalization → queueing →
// translation → filtering). We side-step having to parse pf.conf by anchoring
// our insertions to the well-known Apple defaults that ship in every macOS
// pf.conf since Lion: `rdr-anchor "com.apple/*"` (translation) and
// `anchor "com.apple/*"` (filter). Each abox line goes immediately after its
// same-type Apple sibling, guaranteeing correct section placement without
// any heuristics about what counts as a "filter rule".
//
// If either marker is missing — e.g., on a hand-rolled or MDM-managed pf.conf
// — we refuse to modify the file and tell the user to add the two references
// themselves. We do not guess.
const (
	// PfconfDefaultPath is the standard macOS PF main ruleset.
	PfconfDefaultPath = "/etc/pf.conf"

	// Marker lines we anchor insertions to. These ship in every macOS pf.conf
	// out of the box; if a user removed them, they have a custom config we
	// shouldn't touch.
	pfconfRdrAnchorMarker    = `rdr-anchor "com.apple/*"`
	pfconfFilterAnchorMarker = `anchor "com.apple/*"`

	// Lines we insert. Same form macOS uses for its own anchors so they read
	// as obviously-related additions.
	pfconfRdrAnchorLine    = `rdr-anchor "abox/*"`
	pfconfFilterAnchorLine = `anchor "abox/*"`
)

// ensureAnchorReferences inserts the abox anchor references into pf.conf if
// not already present. Returns changed=true if the file was modified.
//
// Both lines are checked independently: if only one is present we add only
// the missing one, so partial-state pf.conf files (e.g. user wrote one line,
// we wrote the other) converge correctly.
//
// Errors with no file modification when the Apple marker lines are absent;
// the caller (Enable) propagates that error so the user sees it instead of
// silent failure.
func ensureAnchorReferences(path string) (bool, error) {
	original, mode, err := readPfconf(path)
	if err != nil {
		return false, err
	}

	hasRdr := containsLine(original, pfconfRdrAnchorLine)
	hasFilter := containsLine(original, pfconfFilterAnchorLine)
	if hasRdr && hasFilter {
		return false, nil
	}

	hasRdrMarker := containsLine(original, pfconfRdrAnchorMarker)
	hasFilterMarker := containsLine(original, pfconfFilterAnchorMarker)
	if !hasRdrMarker || !hasFilterMarker {
		return false, fmt.Errorf(
			"%s does not contain the expected Apple anchor lines "+
				"(`%s` and `%s`). Add the following to pf.conf manually — "+
				"`%s` in the translation section and `%s` in the filter section — "+
				"then re-run abox start",
			path,
			pfconfRdrAnchorMarker, pfconfFilterAnchorMarker,
			pfconfRdrAnchorLine, pfconfFilterAnchorLine,
		)
	}

	updated := original
	if !hasRdr {
		updated = insertAfterLine(updated, pfconfRdrAnchorMarker, pfconfRdrAnchorLine)
	}
	if !hasFilter {
		updated = insertAfterLine(updated, pfconfFilterAnchorMarker, pfconfFilterAnchorLine)
	}
	updated = ensureTrailingNewline(updated)

	if err := atomicWrite(path, []byte(updated), mode, validateCandidate(path, updated)); err != nil {
		return false, attributePfconfFailure(path, err)
	}
	return true, nil
}

// removeAnchorReferences strips both abox anchor reference lines from pf.conf.
// Returns changed=true if anything was removed. Removes by exact line match,
// so hand-placed copies are also removed — that's intentional, the contract
// is "after teardown, pf.conf has no abox references."
func removeAnchorReferences(path string) (bool, error) {
	original, mode, err := readPfconf(path)
	if err != nil {
		return false, err
	}

	updated, removed := removeLines(original, pfconfRdrAnchorLine, pfconfFilterAnchorLine)
	if !removed {
		return false, nil
	}
	// Keep the newline normalization ensureAnchorReferences applied on the way
	// in, so wire→teardown→wire converges instead of oscillating.
	updated = ensureTrailingNewline(updated)

	// No dry run here: the removal itself must land even when the surrounding
	// pf.conf is unparseable, otherwise a broken host config would pin abox's
	// anchor references in place permanently. Removing lines cannot introduce a
	// syntax error that wasn't already there. TeardownConfig still attempts the
	// reload afterwards and reports separately if the kernel rejects the result.
	if err := atomicWrite(path, []byte(updated), mode, nil); err != nil {
		return false, err
	}
	return true, nil
}

// HasAnchorReferences reports whether both abox anchor references are present
// in pf.conf. Used by `abox doctor`. Read-only; no privileges required since
// pf.conf is mode 0644 by default.
func HasAnchorReferences(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	content := string(data)
	return containsLine(content, pfconfRdrAnchorLine) &&
		containsLine(content, pfconfFilterAnchorLine), nil
}

// CanAutoWireAnchors reports whether ensureAnchorReferences would be able to
// edit pf.conf — i.e. whether both Apple marker lines are present. Returns
// false on hand-rolled or MDM-managed pf.conf where the user must add the
// abox lines themselves. Read-only; no privileges required.
func CanAutoWireAnchors(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	content := string(data)
	return containsLine(content, pfconfRdrAnchorMarker) &&
		containsLine(content, pfconfFilterAnchorMarker), nil
}

// ensureTrailingNewline appends a newline when content lacks one. pf's grammar
// terminates every statement with a newline, so a pf.conf whose final line is a
// rule with no trailing newline is a syntax error at EOF — pfctl reports it as
// "<file>:<lastline+1>: syntax error", a complaint about a line that does not
// exist. Normalizing on write also closes the case where insertAfterLine's
// last-line branch would otherwise have abox generate such a file itself.
// Empty content is left empty rather than turned into a bare newline.
func ensureTrailingNewline(content string) string {
	if content == "" || strings.HasSuffix(content, "\n") {
		return content
	}
	return content + "\n"
}

// pfctlDryRun parses a pf.conf without loading it (`pfctl -n -f`) and returns
// pfctl's combined output alongside any error. Overridable in tests, which have
// neither pfctl nor root.
var pfctlDryRun = func(path string) (string, error) {
	cmd, err := safeCommand("-n", "-f", path)
	if err != nil {
		return "", err
	}
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// validateCandidate returns a validator that parses the pending pf.conf before
// it is renamed into place, so a rejected config is never written to the real
// path even transiently. realPath is only used to rewrite the temp path out of
// pfctl's diagnostics; content is used to echo the offending line.
//
// This is deliberately stricter than the reload-then-roll-back path in
// PfServer.Enable: rolling back means the user's pf.conf briefly held rules the
// kernel refused, and a crash in between would strand it there.
func validateCandidate(realPath, content string) func(string) error {
	return func(tmpPath string) error {
		output, err := pfctlDryRun(tmpPath)
		if err == nil {
			return nil
		}
		output = strings.ReplaceAll(output, tmpPath, realPath)
		return &pfconfValidationError{
			err: fmt.Errorf("%s: %w", describePfctlFailure(output, content), err),
		}
	}
}

// pfconfValidationError marks a failure produced by the pre-commit pfctl dry
// run, as distinct from an I/O failure inside atomicWrite. Only a validation
// failure warrants asking whether the baseline pf.conf was already broken;
// re-attributing a chmod or rename error would bury the real cause.
type pfconfValidationError struct{ err error }

func (e *pfconfValidationError) Error() string { return e.err.Error() }
func (e *pfconfValidationError) Unwrap() error { return e.err }

// pfctlDiagnosticRE matches the "<file>:<line>: <message>" diagnostics pfctl
// emits for parse failures. Anchored per-line so a multi-line pfctl report
// yields its first positioned complaint.
var pfctlDiagnosticRE = regexp.MustCompile(`(?m)^.*?:([0-9]+): `)

// describePfctlFailure augments pfctl's output with the source line it points
// at. pfctl reports a position but never echoes the offending text, and when
// the position is one past the last line the real fault is an unterminated
// final statement — the single most confusing pf.conf failure mode, so it gets
// named explicitly.
func describePfctlFailure(output, content string) string {
	out := strings.TrimSpace(output)

	match := pfctlDiagnosticRE.FindStringSubmatch(out)
	if match == nil {
		return out
	}
	lineNo, err := strconv.Atoi(match[1])
	if err != nil {
		return out
	}

	lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	if lineNo >= 1 && lineNo <= len(lines) {
		return fmt.Sprintf("%s (line %d is %q)", out, lineNo, lines[lineNo-1])
	}
	return fmt.Sprintf("%s (the file has only %d lines, so pfctl is reporting an "+
		"error at end-of-file: the last statement is not terminated)", out, len(lines))
}

// attributePfconfFailure distinguishes "abox's edit broke pf.conf" from "pf.conf
// was already unparseable". Without this the user sees a pfctl syntax error
// immediately after abox touched the file and reasonably blames abox, when the
// fault is pre-existing host config that also fails to load at boot.
//
// Only reached on the failure path, so the extra pfctl invocation costs nothing
// in the common case.
func attributePfconfFailure(path string, err error) error {
	var validationErr *pfconfValidationError
	if !errors.As(err, &validationErr) {
		return err
	}

	output, baseErr := pfctlDryRun(path)
	if baseErr == nil {
		return err
	}
	return fmt.Errorf(
		"%s does not parse even before abox modifies it, so this is a "+
			"pre-existing problem with your pf.conf rather than one abox "+
			"introduced (it will also be failing to load at boot). pf.conf was "+
			"left unchanged. pfctl reported: %s",
		path, describePfctlFailure(output, readForDiagnostics(path)))
}

// readForDiagnostics reads path for error-message enrichment only. A read
// failure yields "" — describePfctlFailure then just omits the line echo, which
// is strictly better than masking the original error with an I/O one.
func readForDiagnostics(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

// readPfconf reads pf.conf and returns its content and current mode.
func readPfconf(path string) (string, os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", 0, fmt.Errorf("stat %s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, fmt.Errorf("read %s: %w", path, err)
	}
	return string(data), info.Mode().Perm(), nil
}

// containsLine reports whether content contains a line whose trimmed form
// matches the trimmed target. Comments (`#`-prefixed lines) never match.
func containsLine(content, target string) bool {
	want := strings.TrimSpace(target)
	for line := range strings.SplitSeq(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == want {
			return true
		}
	}
	return false
}

// insertAfterLine inserts a new line directly after the first non-comment
// line whose trimmed form matches marker. The inserted line uses the same
// indentation as the marker so the result reads naturally.
//
// If marker isn't found, content is returned unchanged. Callers must verify
// presence first via containsLine.
func insertAfterLine(content, marker, newLine string) string {
	want := strings.TrimSpace(marker)

	offset := 0
	for {
		nl := strings.IndexByte(content[offset:], '\n')
		var lineEnd int
		var lineText string
		if nl < 0 {
			lineEnd = len(content)
			lineText = content[offset:]
		} else {
			lineEnd = offset + nl
			lineText = content[offset:lineEnd]
		}

		trimmed := strings.TrimSpace(lineText)
		if !strings.HasPrefix(trimmed, "#") && trimmed == want {
			indent := leadingWhitespace(lineText)
			insertion := indent + newLine + "\n"

			if nl < 0 {
				// Marker is the last line and lacks a trailing newline; add
				// one before our insertion so we don't merge them.
				return content + "\n" + insertion[:len(insertion)-1]
			}
			return content[:lineEnd+1] + insertion + content[lineEnd+1:]
		}

		if nl < 0 {
			return content
		}
		offset = lineEnd + 1
	}
}

// removeLines drops every non-comment line whose trimmed form matches any
// target. Returns updated content and whether any line was removed. Newline
// structure of surviving lines is preserved.
func removeLines(content string, targets ...string) (string, bool) {
	wants := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		wants[strings.TrimSpace(t)] = struct{}{}
	}

	var b strings.Builder
	b.Grow(len(content))
	removed := false

	for _, chunk := range strings.SplitAfter(content, "\n") {
		body := strings.TrimRight(chunk, "\n")
		trimmed := strings.TrimSpace(body)
		if _, ok := wants[trimmed]; ok && !strings.HasPrefix(trimmed, "#") {
			removed = true
			continue
		}
		b.WriteString(chunk)
	}

	return b.String(), removed
}

// leadingWhitespace returns the run of spaces/tabs at the start of s.
func leadingWhitespace(s string) string {
	for i, r := range s {
		if r != ' ' && r != '\t' {
			return s[:i]
		}
	}
	return s
}

// atomicWrite writes data to path via a tempfile-and-rename so a crash mid-write
// can't leave pf.conf truncated. Mode is preserved from the original file.
//
// If validate is non-nil it is called with the temp file's path after the
// content and mode are final but before the rename. A non-nil error aborts the
// write and leaves path completely untouched, so a config that pfctl rejects
// never reaches the real path.
func atomicWrite(path string, data []byte, mode os.FileMode, validate func(string) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".abox-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if validate != nil {
		if err := validate(tmpPath); err != nil {
			return err
		}
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	cleanup = false
	return nil
}
