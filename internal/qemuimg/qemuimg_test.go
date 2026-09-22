package qemuimg

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

// requireQemuImg skips the test when qemu-img is not on PATH so the suite stays
// portable/CI-safe.
func requireQemuImg(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not installed; skipping round-trip test")
	}
}

// imgFormat returns the format qemu-img reports for path.
func imgFormat(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command("qemu-img", "info", "--output=json", path).Output()
	if err != nil {
		t.Fatalf("qemu-img info failed: %v", err)
	}
	var v struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("parse qemu-img info: %v", err)
	}
	return v.Format
}

// captureQemuArgv installs the runCmd seam so builders record their argv into the
// returned slice pointer instead of invoking qemu-img (a harmless `true` runs so
// callers' .Output()/.CombinedOutput() succeed). Restored via t.Cleanup.
func captureQemuArgv(t *testing.T) *[]string {
	t.Helper()
	got := &[]string{}
	prev := runCmd
	runCmd = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		*got = append([]string(nil), args...)
		return exec.CommandContext(ctx, "true")
	}
	t.Cleanup(func() { runCmd = prev })
	return got
}

// assertDashBefore verifies argv contains "--" immediately before the final
// `tail` path positionals, so a path starting with "-" can't be parsed as a flag.
func assertDashBefore(t *testing.T, got []string, name string, tail int) {
	t.Helper()
	if len(got) < tail+1 {
		t.Fatalf("%s: argv too short: %v", name, got)
	}
	if sep := got[len(got)-tail-1]; sep != "--" {
		t.Errorf("%s: argv element before path(s) = %q, want %q (argv=%v)", name, sep, "--", got)
	}
}

// assertArgvPrefix verifies got begins with want.
func assertArgvPrefix(t *testing.T, got []string, name string, want ...string) {
	t.Helper()
	if len(got) < len(want) {
		t.Errorf("%s: argv = %v, want prefix %v", name, got, want)
		return
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("%s: argv = %v, want prefix %v", name, got, want)
			return
		}
	}
}

// TestBuildersInsertDoubleDash asserts every qemu-img builder inserts the "--"
// end-of-options separator immediately before its trailing path positional(s),
// so a path that starts with "-" can never be parsed as a flag.
func TestBuildersInsertDoubleDash(t *testing.T) {
	got := captureQemuArgv(t)
	ctx := context.Background()

	// Format / BackingFile parse JSON output; `true` emits none, so ignore the
	// returned parse error — we only assert on the captured argv.
	_, _ = Format(ctx, "/path")
	assertDashBefore(t, *got, "Format", 1)
	_, _ = BackingFile(ctx, "/path")
	assertDashBefore(t, *got, "BackingFile", 1)
	_ = Rebase(ctx, "/disk", "/backing")
	assertDashBefore(t, *got, "Rebase", 1)
	_ = Check(ctx, "/disk")
	assertDashBefore(t, *got, "Check", 1)
	_ = Create(ctx, "/backing", "/output", "8M")
	assertDashBefore(t, *got, "Create", 2) // <output> <size>
	_ = Convert(ctx, "/src", "/dst", false)
	assertDashBefore(t, *got, "Convert", 2)
	_ = ConvertFrom(ctx, "/src", "/dst", "raw")
	assertDashBefore(t, *got, "ConvertFrom", 2)
	_ = ConvertToVMDK(ctx, "/src", "/dst")
	assertDashBefore(t, *got, "ConvertToVMDK", 2)
	_ = FlattenVMDK(ctx, "/src", "/dst")
	assertDashBefore(t, *got, "FlattenVMDK", 2)
	_ = ConvertVMDKToQcow2(ctx, "/src", "/dst")
	assertDashBefore(t, *got, "ConvertVMDKToQcow2", 2)
	_ = ConvertVMDKToVMDK(ctx, "/src", "/dst")
	assertDashBefore(t, *got, "ConvertVMDKToVMDK", 2)
	_ = ConvertToRaw(ctx, "/src", "qcow2", "/dst")
	assertDashBefore(t, *got, "ConvertToRaw", 2)
	_ = ConvertToQcow2Compressed(ctx, "/src", "raw", "/dst")
	assertDashBefore(t, *got, "ConvertToQcow2Compressed", 2)
}

// TestBuilderArgvPrefixes pins the exact flag prefixes for the security-relevant
// builders: the untrusted-import converts must pin the source format (never
// re-probe), and Check must open the whole backing chain without a consistency
// scan.
func TestBuilderArgvPrefixes(t *testing.T) {
	got := captureQemuArgv(t)
	ctx := context.Background()

	_ = Check(ctx, "/disk")
	assertArgvPrefix(t, *got, "Check", "info", "--backing-chain", "--output=json", "--", "/disk")

	_ = ConvertFrom(ctx, "/src", "/dst", "raw")
	assertArgvPrefix(t, *got, "ConvertFrom", "convert", "-f", "raw")

	_ = ConvertVMDKToVMDK(ctx, "/src", "/dst")
	assertArgvPrefix(t, *got, "ConvertVMDKToVMDK", "convert", "-f", "vmdk", "-O", "vmdk")

	_ = ConvertToRaw(ctx, "/src", "qcow2", "/dst")
	assertArgvPrefix(t, *got, "ConvertToRaw", "convert", "-f", "qcow2", "-O", "raw")

	_ = ConvertToQcow2Compressed(ctx, "/src", "raw", "/dst")
	assertArgvPrefix(t, *got, "ConvertToQcow2Compressed", "convert", "-c", "-f", "raw", "-O", "qcow2")
}

func TestConvertToVMDK(t *testing.T) {
	requireQemuImg(t)

	dir := t.TempDir()
	srcQcow2 := filepath.Join(dir, "src.qcow2")
	dstVMDK := filepath.Join(dir, "out.vmdk")

	ctx := context.Background()

	// Create a tiny real qcow2 (standalone, no backing file).
	cmd := exec.CommandContext(ctx, "qemu-img", "create", "-f", "qcow2", srcQcow2, "8M")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create source qcow2: %s: %v", out, err)
	}

	if err := ConvertToVMDK(ctx, srcQcow2, dstVMDK); err != nil {
		t.Fatalf("ConvertToVMDK: %v", err)
	}

	if got := imgFormat(t, dstVMDK); got != "vmdk" {
		t.Fatalf("output format = %q, want vmdk", got)
	}
}

func TestFlattenVMDK(t *testing.T) {
	requireQemuImg(t)

	dir := t.TempDir()
	ctx := context.Background()

	srcQcow2 := filepath.Join(dir, "src.qcow2")
	baseVMDK := filepath.Join(dir, "base.vmdk")
	flat := filepath.Join(dir, "flat.vmdk")

	if out, err := exec.CommandContext(ctx, "qemu-img", "create", "-f", "qcow2", srcQcow2, "8M").CombinedOutput(); err != nil {
		t.Fatalf("create qcow2: %s: %v", out, err)
	}
	if err := ConvertToVMDK(ctx, srcQcow2, baseVMDK); err != nil {
		t.Fatalf("ConvertToVMDK: %v", err)
	}
	if err := FlattenVMDK(ctx, baseVMDK, flat); err != nil {
		t.Fatalf("FlattenVMDK: %v", err)
	}
	if got := imgFormat(t, flat); got != "vmdk" {
		t.Fatalf("flattened format = %q, want vmdk", got)
	}
}

func TestConvertVMDKToQcow2(t *testing.T) {
	requireQemuImg(t)

	dir := t.TempDir()
	ctx := context.Background()

	srcQcow2 := filepath.Join(dir, "src.qcow2")
	baseVMDK := filepath.Join(dir, "base.vmdk")
	outQcow2 := filepath.Join(dir, "out.qcow2")

	if out, err := exec.CommandContext(ctx, "qemu-img", "create", "-f", "qcow2", srcQcow2, "8M").CombinedOutput(); err != nil {
		t.Fatalf("create qcow2: %s: %v", out, err)
	}
	if err := ConvertToVMDK(ctx, srcQcow2, baseVMDK); err != nil {
		t.Fatalf("ConvertToVMDK: %v", err)
	}
	if err := ConvertVMDKToQcow2(ctx, baseVMDK, outQcow2); err != nil {
		t.Fatalf("ConvertVMDKToQcow2: %v", err)
	}
	if got := imgFormat(t, outQcow2); got != "qcow2" {
		t.Fatalf("output format = %q, want qcow2", got)
	}
}

// TestRejectExternalReferences verifies the import guard rejects every external
// reference qemu-img reports — a backing file (unless tolerated for a snapshot
// import) and, critically, a qcow2 external data file (the HIGH-1 bypass, which is
// orthogonal to the backing chain and must be rejected even when a backing file is
// allowed). The runCmd seam feeds a canned `qemu-img info` JSON so no real image
// is needed.
func TestRejectExternalReferences(t *testing.T) {
	ctx := context.Background()
	stub := func(jsonOut string) func() {
		prev := runCmd
		runCmd = func(ctx context.Context, name string, args ...string) *exec.Cmd {
			return exec.CommandContext(ctx, "printf", "%s", jsonOut)
		}
		return func() { runCmd = prev }
	}

	cases := []struct {
		name    string
		json    string
		opts    ExternalRefOpts
		wantErr bool
	}{
		{"self-contained", `{"format":"qcow2"}`, ExternalRefOpts{}, false},
		{"backing file rejected", `{"format":"qcow2","backing-filename":"/evil/base.qcow2"}`, ExternalRefOpts{}, true},
		{"backing file allowed for snapshot", `{"format":"qcow2","backing-filename":"/local/base.qcow2"}`, ExternalRefOpts{AllowBackingFile: true}, false},
		{"data-file rejected", `{"format":"qcow2","format-specific":{"data":{"data-file":"/etc/shadow"}}}`, ExternalRefOpts{}, true},
		{"data-file rejected even when backing allowed", `{"format":"qcow2","backing-filename":"/local/base.qcow2","format-specific":{"data":{"data-file":"/etc/shadow"}}}`, ExternalRefOpts{AllowBackingFile: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restore := stub(tc.json)
			defer restore()
			err := RejectExternalReferences(ctx, "/img", "must be self-contained", "flatten it", tc.opts)
			if tc.wantErr && err == nil {
				t.Fatalf("expected rejection, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected accept, got %v", err)
			}
		})
	}

	// The RejectBackingFile wrapper must also reject a data-file (it tolerates no
	// external reference at all).
	restore := stub(`{"format":"qcow2","format-specific":{"data":{"data-file":"/etc/shadow"}}}`)
	defer restore()
	if err := RejectBackingFile(ctx, "/img", "must be self-contained", "flatten it"); err == nil {
		t.Fatalf("RejectBackingFile: expected data-file rejection, got nil")
	}
}
