package vmrun

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBaseVMDKPath(t *testing.T) {
	got := BaseVMDKPath("/store/base", "ubuntu-24.04")
	want := filepath.Join("/store/base", "ubuntu-24.04.vmdk")
	if got != want {
		t.Fatalf("BaseVMDKPath = %q, want %q", got, want)
	}
}

func TestInstanceVMDKPath(t *testing.T) {
	got := InstanceVMDKPath("/store/instances/dev")
	want := filepath.Join("/store/instances/dev", "disk.vmdk")
	if got != want {
		t.Fatalf("InstanceVMDKPath = %q, want %q", got, want)
	}
}

// writePlainVMDK writes a plain-text VMDK descriptor file (no sparse header).
func writePlainVMDK(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeSparseVMDK writes a monolithicSparse VMDK with the given descriptor
// embedded via a valid sparse extent header, so readVMDKDescriptor exercises the
// header path (not the plain-text fallback).
func writeSparseVMDK(t *testing.T, dir, name, descriptor string) string {
	t.Helper()
	path := filepath.Join(dir, name)

	const sector = 512
	descOffsetSectors := uint64(1) // descriptor starts at sector 1 (after header)
	descBytes := []byte(descriptor)
	descSizeSectors := uint64((len(descBytes) + sector - 1) / sector)
	if descSizeSectors == 0 {
		descSizeSectors = 1
	}

	var hdr [sector]byte
	binary.LittleEndian.PutUint32(hdr[0:4], vmdkSparseMagic)
	binary.LittleEndian.PutUint32(hdr[4:8], 1) // version
	binary.LittleEndian.PutUint64(hdr[28:36], descOffsetSectors)
	binary.LittleEndian.PutUint64(hdr[36:44], descSizeSectors)

	buf := make([]byte, sector+int(descSizeSectors)*sector)
	copy(buf[0:sector], hdr[:])
	copy(buf[sector:], descBytes)

	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateSelfContainedVMDK_Accepts(t *testing.T) {
	dir := t.TempDir()

	cases := map[string]string{
		"plain self-contained": "# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\ncreateType=\"monolithicSparse\"\nRW 16384 SPARSE \"disk-s001.vmdk\"\n",
		"no extents":           "# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\n",
		"relative subdir":      "# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\nRW 16384 FLAT \"sub/disk-flat.vmdk\" 0\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := writePlainVMDK(t, dir, "ok-"+name+".vmdk", body)
			if err := ValidateSelfContainedVMDK(p); err != nil {
				t.Fatalf("expected accept, got %v", err)
			}
		})
	}

	t.Run("embedded sparse descriptor", func(t *testing.T) {
		p := writeSparseVMDK(t, dir, "sparse-ok.vmdk",
			"# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\nRW 16384 SPARSE \"sparse-ok.vmdk\"\n")
		if err := ValidateSelfContainedVMDK(p); err != nil {
			t.Fatalf("expected accept, got %v", err)
		}
	})
}

func TestValidateSelfContainedVMDK_Rejects(t *testing.T) {
	dir := t.TempDir()

	cases := map[string]string{
		"parentFileNameHint": "# Disk DescriptorFile\nversion=1\nparentFileNameHint=\"/some/parent.vmdk\"\nparentCID=12345678\n",
		"parentCID set":      "# Disk DescriptorFile\nversion=1\nparentCID=12345678\nRW 16384 SPARSE \"disk.vmdk\"\n",
		"absolute extent":    "# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\nRW 16384 FLAT \"/etc/shadow\" 0\n",
		"escaping extent":    "# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\nRW 16384 FLAT \"../../etc/shadow\" 0\n",
		"windows absolute":   "# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\nRW 16384 FLAT \"C:\\\\Windows\\\\x\" 0\n",
		// HIGH-2 regression: qemu-img parses extent lines with sscanf semantics, so a
		// tab- (or mixed-whitespace-) delimited extent is a valid FLAT extent to
		// qemu. isExtentLine must tokenize on any whitespace run so checkExtentPath is
		// still reached and the absolute path rejected — before this fix these were
		// silently accepted and the guest booted with /etc/shadow as an extent.
		"tab-delimited absolute extent": "# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\nRW\t16384\tFLAT\t\"/etc/shadow\"\t0\n",
		"mixed-whitespace absolute":     "# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\nRW\t16384 FLAT  \"/etc/shadow\" 0\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := writePlainVMDK(t, dir, "bad-"+name+".vmdk", body)
			if err := ValidateSelfContainedVMDK(p); err == nil {
				t.Fatalf("expected reject for %s, got nil", name)
			}
		})
	}

	t.Run("embedded sparse with parent", func(t *testing.T) {
		p := writeSparseVMDK(t, dir, "sparse-bad.vmdk",
			"# Disk DescriptorFile\nversion=1\nparentFileNameHint=\"/some/parent.vmdk\"\nparentCID=12345678\n")
		if err := ValidateSelfContainedVMDK(p); err == nil {
			t.Fatalf("expected reject for embedded parent, got nil")
		}
	})
}

// TestReadVMDKDescriptor_PlainTextDetection verifies that plain-text descriptor
// detection is a strict superset of qemu-img's vmdk_probe: any file qemu-img would
// open as a VMDK is detected (with or without the "# Disk DescriptorFile" header,
// and past leading comment/blank/whitespace lines), while a qcow2/raw image whose
// body merely contains a "version" substring after its format magic is not
// misclassified.
func TestReadVMDKDescriptor_PlainTextDetection(t *testing.T) {
	dir := t.TempDir()

	// qcow2 magic ("QFI\xfb") at offset 0 followed by a body that happens to
	// contain "version=". Must NOT be treated as a VMDK descriptor.
	qcow2 := append([]byte("QFI\xfb"), []byte("\x00\x00\x00\x03 some data version=1 more data")...)

	cases := []struct {
		name    string
		body    []byte
		wantHit bool
	}{
		{
			name:    "qcow2 body containing version=",
			body:    qcow2,
			wantHit: false,
		},
		{
			name:    "raw body containing version=",
			body:    []byte("\x00\x00 arbitrary raw image bytes with version=1 embedded \x00"),
			wantHit: false,
		},
		{
			name:    "real plain-text descriptor with header",
			body:    []byte("# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\ncreateType=\"monolithicSparse\"\n"),
			wantHit: true,
		},
		{
			// The bypass this fix closes: a descriptor with no "# Disk
			// DescriptorFile" header. qemu-img still probes it as vmdk, so we must
			// too, or the self-containment validation is skipped.
			name:    "header-less descriptor",
			body:    []byte("version=1\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW 16384 FLAT \"disk-flat.vmdk\" 0\n"),
			wantHit: true,
		},
		{
			// qemu-img skips leading blank/whitespace lines before "version"; a
			// non-superset matcher that stopped at the first '\n' would miss this.
			name:    "leading blank and space lines",
			body:    []byte("\n   \n\t\nversion=1\nparentCID=ffffffff\n"),
			wantHit: true,
		},
		{
			// qemu-img's probe matches the bare "version" token (strncmp 7 bytes),
			// not "version=<digit>"; be a superset of that.
			name:    "bare version token without equals",
			body:    []byte("version 1\nparentCID=ffffffff\n"),
			wantHit: true,
		},
		{
			name:    "comment lines before version",
			body:    []byte("# some vendor banner\n# another comment\nversion=2\nparentCID=ffffffff\n"),
			wantHit: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "det-"+tc.name+".img")
			if err := os.WriteFile(path, tc.body, 0o600); err != nil {
				t.Fatal(err)
			}
			desc, err := readVMDKDescriptor(path)
			if err != nil {
				t.Fatalf("readVMDKDescriptor: %v", err)
			}
			gotHit := desc != ""
			if gotHit != tc.wantHit {
				t.Fatalf("descriptor detected = %v, want %v (desc=%q)", gotHit, tc.wantHit, desc)
			}
		})
	}
}

// TestIsVMDK_PlainTextDetection is the IsVMDK-level regression guard for the
// same behavior exercised via the exported API.
func TestIsVMDK_PlainTextDetection(t *testing.T) {
	dir := t.TempDir()

	qcow2 := append([]byte("QFI\xfb"), []byte("\x00\x00\x00\x03 body with version= inside")...)
	qpath := filepath.Join(dir, "image.qcow2")
	if err := os.WriteFile(qpath, qcow2, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := IsVMDK(qpath); err != nil {
		t.Fatalf("IsVMDK(qcow2): %v", err)
	} else if got {
		t.Fatalf("qcow2 with version= substring misclassified as VMDK")
	}

	descPath := writePlainVMDK(t, dir, "real.vmdk",
		"# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\ncreateType=\"monolithicSparse\"\n")
	if got, err := IsVMDK(descPath); err != nil {
		t.Fatalf("IsVMDK(descriptor): %v", err)
	} else if !got {
		t.Fatalf("real plain-text VMDK descriptor not detected as VMDK")
	}

	// A header-less descriptor (no "# Disk DescriptorFile" line) must also be
	// detected — this is the case qemu-img would still read as vmdk.
	headerless := writePlainVMDK(t, dir, "headerless.vmdk",
		"version=1\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW 16384 FLAT \"disk-flat.vmdk\" 0\n")
	if got, err := IsVMDK(headerless); err != nil {
		t.Fatalf("IsVMDK(header-less): %v", err)
	} else if !got {
		t.Fatalf("header-less VMDK descriptor not detected as VMDK")
	}
}

// TestValidateImportVMDK_HeaderlessAbsoluteExtent is the regression guard for the
// import bypass: a plain-text descriptor that OMITS the "# Disk DescriptorFile"
// header but names an absolute FLAT extent must be rejected. Before the detector
// was made a superset of qemu-img's probe, IsVMDK returned false for such a file,
// ValidateImportVMDK short-circuited to nil, and `qemu-img convert -f vmdk` would
// read the absolute extent (e.g. a host secret) into the imported image.
func TestValidateImportVMDK_HeaderlessAbsoluteExtent(t *testing.T) {
	dir := t.TempDir()
	p := writePlainVMDK(t, dir, "evil.vmdk",
		"version=1\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW 20971520 FLAT \"/etc/shadow\" 0\n")

	if got, err := IsVMDK(p); err != nil {
		t.Fatalf("IsVMDK: %v", err)
	} else if !got {
		t.Fatalf("header-less malicious VMDK not detected as VMDK (validation would be skipped)")
	}
	if err := ValidateImportVMDK(p); err == nil {
		t.Fatalf("expected ValidateImportVMDK to reject absolute FLAT extent, got nil")
	}
}

// TestInspectImportSource covers the shared import-source validation used by both
// base import and the VMware backend.
func TestInspectImportSource(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	t.Run("self-contained header-less vmdk", func(t *testing.T) {
		p := writePlainVMDK(t, dir, "ok.vmdk",
			"version=1\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW 16384 FLAT \"disk-flat.vmdk\" 0\n")
		got, err := InspectImportSource(ctx, p)
		if err != nil {
			t.Fatalf("InspectImportSource: %v", err)
		}
		if got != "vmdk" {
			t.Fatalf("format = %q, want %q", got, "vmdk")
		}
	})

	t.Run("malicious header-less vmdk rejected", func(t *testing.T) {
		p := writePlainVMDK(t, dir, "bad.vmdk",
			"version=1\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW 20971520 FLAT \"/etc/shadow\" 0\n")
		if _, err := InspectImportSource(ctx, p); err == nil {
			t.Fatalf("expected rejection of absolute FLAT extent, got nil")
		}
	})

	t.Run("qcow2 source detected", func(t *testing.T) {
		if _, err := exec.LookPath("qemu-img"); err != nil {
			t.Skip("qemu-img not installed; skipping content-format detection")
		}
		p := filepath.Join(dir, "src.qcow2")
		if out, err := exec.Command("qemu-img", "create", "-f", "qcow2", p, "1M").CombinedOutput(); err != nil {
			t.Fatalf("qemu-img create: %v: %s", err, out)
		}
		got, err := InspectImportSource(ctx, p)
		if err != nil {
			t.Fatalf("InspectImportSource: %v", err)
		}
		if got != "qcow2" {
			t.Fatalf("format = %q, want %q", got, "qcow2")
		}
	})
}

func TestValidateSelfContainedVMDK_NoDescriptorAccepted(t *testing.T) {
	// A file with no recognizable descriptor is accepted here (other checks cover
	// non-VMDK formats).
	dir := t.TempDir()
	p := filepath.Join(dir, "opaque.bin")
	if err := os.WriteFile(p, []byte("not a descriptor at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSelfContainedVMDK(p); err != nil {
		t.Fatalf("expected accept for non-descriptor file, got %v", err)
	}
}
