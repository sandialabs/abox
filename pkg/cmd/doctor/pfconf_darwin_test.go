//go:build darwin

package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pfconf fixtures mirror the canonical macOS shape so the doctor check sees
// realistic inputs. The marker lines (`rdr-anchor "com.apple/*"` and
// `anchor "com.apple/*"`) are what privilege.CanAutoWireAnchors looks for.
const (
	doctorTestApplePfconf = `#
# Default PF configuration file.
#
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
`

	doctorTestWiredPfconf = `#
# Default PF configuration file.
#
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
rdr-anchor "abox/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
anchor "abox/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
`

	doctorTestCustomPfconf = `#
# Custom pf.conf with no Apple anchors.
#
pass in all
`
)

func writeDoctorPfconf(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pf.conf")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("seed pf.conf: %v", err)
	}
	return path
}

func TestCheckPfAnchorsWired_Wired(t *testing.T) {
	path := writeDoctorPfconf(t, doctorTestWiredPfconf)
	got := checkPfAnchorsWired(path)

	if !got.Passed {
		t.Errorf("Passed = false, want true (Details=%q, Hint=%q)", got.Details, got.Hint)
	}
}

func TestCheckPfAnchorsWired_NotWiredButCanAutoWire(t *testing.T) {
	path := writeDoctorPfconf(t, doctorTestApplePfconf)
	got := checkPfAnchorsWired(path)

	if got.Passed {
		t.Fatal("Passed = true, want false")
	}
	if !strings.Contains(got.Hint, "abox start") {
		t.Errorf("expected hint to mention `abox start`, got %q", got.Hint)
	}
	if strings.Contains(got.Hint, "manually") {
		t.Errorf("hint should NOT tell user to edit manually when auto-wire works, got %q", got.Hint)
	}
}

func TestCheckPfAnchorsWired_CustomPfconf(t *testing.T) {
	path := writeDoctorPfconf(t, doctorTestCustomPfconf)
	got := checkPfAnchorsWired(path)

	if got.Passed {
		t.Fatal("Passed = true, want false")
	}
	for _, want := range []string{"custom", "manually", `rdr-anchor "abox/*"`, `anchor "abox/*"`} {
		if !strings.Contains(got.Hint, want) {
			t.Errorf("hint missing %q:\n%s", want, got.Hint)
		}
	}
	// Must not point the user at `abox start` — that flow will fail with the
	// missing-markers error.
	if strings.Contains(got.Hint, "abox start") {
		t.Errorf("hint should NOT suggest `abox start` for custom pf.conf, got %q", got.Hint)
	}
}

func TestCheckPfAnchorsWired_MissingFile(t *testing.T) {
	got := checkPfAnchorsWired(filepath.Join(t.TempDir(), "does-not-exist"))

	if got.Passed {
		t.Fatal("Passed = true on missing file, want false")
	}
	if got.Details == "" {
		t.Error("Details should describe the read error")
	}
}
