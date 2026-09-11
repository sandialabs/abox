//go:build darwin

package privilege

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// defaultPfconf is a representative macOS /etc/pf.conf with the Apple markers
// abox anchors its insertions to.
const defaultPfconf = `#
# Default PF configuration file.
#
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
`

// writeTempPfconf seeds a temp pf.conf and stubs the pfctl dry run to succeed.
// Tests have neither pfctl nor root, and the validator is exercised separately
// by the tests that install their own stub.
func writeTempPfconf(t *testing.T, content string) string {
	t.Helper()
	stubPfctlDryRun(t, func(string) (string, error) { return "", nil })
	path := filepath.Join(t.TempDir(), "pf.conf")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp pf.conf: %v", err)
	}
	return path
}

// stubPfctlDryRun replaces the pfctl dry run for the duration of one test.
func stubPfctlDryRun(t *testing.T, fn func(string) (string, error)) {
	t.Helper()
	original := pfctlDryRun
	pfctlDryRun = fn
	t.Cleanup(func() { pfctlDryRun = original })
}

func TestEnsureAnchorReferences_WiresAndIsIdempotent(t *testing.T) {
	path := writeTempPfconf(t, defaultPfconf)

	changed, err := ensureAnchorReferences(path)
	if err != nil {
		t.Fatalf("first ensureAnchorReferences: %v", err)
	}
	if !changed {
		t.Fatal("first wiring should report changed=true")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, pfconfRdrAnchorLine) {
		t.Errorf("rdr anchor line not inserted: %q", content)
	}
	if !strings.Contains(content, pfconfFilterAnchorLine) {
		t.Errorf("filter anchor line not inserted: %q", content)
	}
	// rdr line must sit after the rdr marker; filter line after the filter marker.
	if idx := strings.Index(content, pfconfRdrAnchorLine); idx < strings.Index(content, pfconfRdrAnchorMarker) {
		t.Error("rdr abox line should follow the rdr Apple marker")
	}
	if idx := strings.Index(content, pfconfFilterAnchorLine); idx < strings.Index(content, pfconfFilterAnchorMarker) {
		t.Error("filter abox line should follow the filter Apple marker")
	}

	// Second call: no-op.
	changed, err = ensureAnchorReferences(path)
	if err != nil {
		t.Fatalf("second ensureAnchorReferences: %v", err)
	}
	if changed {
		t.Fatal("second wiring should be a no-op (changed=false)")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != content {
		t.Fatal("second wiring must not modify the file")
	}
}

func TestEnsureAnchorReferences_MissingAppleMarkers(t *testing.T) {
	path := writeTempPfconf(t, "# hand-rolled pf.conf with no Apple anchors\nset skip on lo0\n")

	changed, err := ensureAnchorReferences(path)
	if err == nil {
		t.Fatal("expected an error when Apple markers are absent")
	}
	if changed {
		t.Fatal("must not report changed when it refuses to edit")
	}

	// The file must be left untouched.
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "abox/*") {
		t.Fatal("file should not be modified when markers are missing")
	}
}

func TestEnsureAnchorReferences_PartialState(t *testing.T) {
	// Only the rdr line is already present; ensure only the filter line is added.
	partial := strings.Replace(defaultPfconf,
		`rdr-anchor "com.apple/*"`,
		"rdr-anchor \"com.apple/*\"\n"+pfconfRdrAnchorLine, 1)
	path := writeTempPfconf(t, partial)

	changed, err := ensureAnchorReferences(path)
	if err != nil {
		t.Fatalf("ensureAnchorReferences: %v", err)
	}
	if !changed {
		t.Fatal("expected the missing filter line to be added")
	}

	has, err := HasAnchorReferences(path)
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatal("both anchor references should now be present")
	}
}

func TestRemoveAnchorReferences(t *testing.T) {
	path := writeTempPfconf(t, defaultPfconf)
	if _, err := ensureAnchorReferences(path); err != nil {
		t.Fatalf("wire: %v", err)
	}

	changed, err := removeAnchorReferences(path)
	if err != nil {
		t.Fatalf("removeAnchorReferences: %v", err)
	}
	if !changed {
		t.Fatal("removal should report changed=true")
	}

	has, err := HasAnchorReferences(path)
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatal("no abox anchor references should remain")
	}

	// Second removal is a no-op.
	changed, err = removeAnchorReferences(path)
	if err != nil {
		t.Fatalf("second removeAnchorReferences: %v", err)
	}
	if changed {
		t.Fatal("second removal should be a no-op")
	}
}

func TestCanAutoWireAnchors(t *testing.T) {
	withMarkers := writeTempPfconf(t, defaultPfconf)
	ok, err := CanAutoWireAnchors(withMarkers)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected CanAutoWireAnchors=true for a default pf.conf")
	}

	noMarkers := writeTempPfconf(t, "set skip on lo0\n")
	ok, err = CanAutoWireAnchors(noMarkers)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected CanAutoWireAnchors=false for a hand-rolled pf.conf")
	}
}

// pfconfNoTrailingNewline reproduces the real-world file that motivated the
// newline handling: a site-managed `load anchor` line appended without a
// terminating newline. pf's grammar terminates every statement with '\n', so
// pfctl rejects the whole file and blames a line one past its end.
const pfconfNoTrailingNewline = `#
# Default PF configuration file.
#
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
load anchor "gov.sandia.pf" from "/etc/pf.anchors/gov.sandia.pf"`

func TestEnsureAnchorReferences_AddsMissingTrailingNewline(t *testing.T) {
	path := writeTempPfconf(t, pfconfNoTrailingNewline)

	if _, err := ensureAnchorReferences(path); err != nil {
		t.Fatalf("ensureAnchorReferences: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Fatal("wired pf.conf must end with a newline or pfctl rejects the whole file")
	}
	// The site's own trailing directive must survive intact.
	if !strings.Contains(string(data), `load anchor "gov.sandia.pf" from "/etc/pf.anchors/gov.sandia.pf"`) {
		t.Errorf("pre-existing load anchor line was lost: %q", string(data))
	}
	if strings.HasSuffix(string(data), "\n\n") {
		t.Error("must not accumulate blank lines at EOF")
	}
}

func TestEnsureAnchorReferences_RejectedCandidateLeavesFileUntouched(t *testing.T) {
	path := writeTempPfconf(t, defaultPfconf)
	// Candidate parse fails, baseline parse succeeds -> abox's edit is at fault.
	stubPfctlDryRun(t, func(p string) (string, error) {
		if strings.HasSuffix(p, "pf.conf") {
			return "", nil
		}
		return p + ":5: syntax error", errors.New("exit status 1")
	})

	changed, err := ensureAnchorReferences(path)
	if err == nil {
		t.Fatal("expected an error when the candidate fails to parse")
	}
	if changed {
		t.Error("must not report changed when the write was aborted")
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != defaultPfconf {
		t.Errorf("pf.conf must be byte-identical after a rejected candidate, got %q", string(data))
	}
	// The temp path must not leak into the message the user reads.
	if strings.Contains(err.Error(), ".abox-tmp-") {
		t.Errorf("error should report the real pf.conf path, got %q", err.Error())
	}

	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".abox-tmp-") {
			t.Errorf("temp file %q leaked after a rejected candidate", e.Name())
		}
	}
}

func TestEnsureAnchorReferences_PreExistingBreakageIsAttributed(t *testing.T) {
	path := writeTempPfconf(t, defaultPfconf)
	// Both candidate and baseline fail -> pf.conf was already broken.
	stubPfctlDryRun(t, func(p string) (string, error) {
		return p + ":9: syntax error", errors.New("exit status 1")
	})

	_, err := ensureAnchorReferences(path)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "pre-existing") {
		t.Errorf("error must attribute the failure to the host's pf.conf, got %q", err.Error())
	}
}

func TestRemoveAnchorReferences_SucceedsOnUnparseablePfconf(t *testing.T) {
	path := writeTempPfconf(t, defaultPfconf)
	if _, err := ensureAnchorReferences(path); err != nil {
		t.Fatalf("wire: %v", err)
	}

	// Teardown must not consult pfctl at all: a host whose pf.conf cannot parse
	// still has to be able to remove abox's references.
	stubPfctlDryRun(t, func(p string) (string, error) {
		t.Errorf("removeAnchorReferences must not dry-run pfctl (called with %q)", p)
		return "", errors.New("exit status 1")
	})

	changed, err := removeAnchorReferences(path)
	if err != nil {
		t.Fatalf("removeAnchorReferences: %v", err)
	}
	if !changed {
		t.Fatal("expected the references to be removed")
	}
}

func TestDescribePfctlFailure(t *testing.T) {
	content := "line one\nline two\nline three\n"

	// A position inside the file echoes the offending line.
	got := describePfctlFailure("/etc/pf.conf:2: syntax error", content)
	if !strings.Contains(got, `"line two"`) {
		t.Errorf("expected the offending line to be echoed, got %q", got)
	}

	// A position past the end names the unterminated-statement case.
	got = describePfctlFailure("/etc/pf.conf:4: syntax error", content)
	if !strings.Contains(got, "end-of-file") {
		t.Errorf("expected an end-of-file explanation, got %q", got)
	}

	// Output with no position is passed through unchanged.
	got = describePfctlFailure("pfctl: /dev/pf: Permission denied", content)
	if got != "pfctl: /dev/pf: Permission denied" {
		t.Errorf("unpositioned output should pass through, got %q", got)
	}
}
