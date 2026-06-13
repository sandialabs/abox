//go:build darwin

package privilege

import (
	"fmt"
	"os"
	"path/filepath"
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
// the caller (PfctlEnable) propagates that error so the user sees it instead
// of silent failure.
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

	if err := atomicWrite(path, []byte(updated), mode); err != nil {
		return false, err
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

	if err := atomicWrite(path, []byte(updated), mode); err != nil {
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

	for chunk := range strings.SplitAfterSeq(content, "\n") {
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
func atomicWrite(path string, data []byte, mode os.FileMode) error {
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
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	cleanup = false
	return nil
}
