package vmrun

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/sandialabs/abox/internal/errhint"
	"github.com/sandialabs/abox/internal/qemuimg"
)

// formatVMDK is the qemu-img format name for a VMDK image.
const formatVMDK = "vmdk"

// BaseVMDKPath returns the path of the base VMDK for the named base image inside
// baseImagesDir: <baseImagesDir>/<base>.vmdk. Per-instance disks are full,
// standalone copies of this file (see the vmware backend DiskManager).
func BaseVMDKPath(baseImagesDir, base string) string {
	return filepath.Join(baseImagesDir, base+".vmdk")
}

// InstanceVMDKPath returns the per-instance disk path inside diskDir:
// <diskDir>/disk.vmdk. NOTE: config.Paths.Disk is hardcoded to "disk.qcow2"
// (libvirt's format); the VMware backend derives its own ".vmdk" path here so
// the two formats do not collide. The later wiring phase must route VMware
// instances through this path rather than paths.Disk.
func InstanceVMDKPath(diskDir string) string {
	return filepath.Join(diskDir, "disk.vmdk")
}

// vmdkSparseMagic is the VMDK sparse extent header magic, "KDMV", stored
// little-endian at the start of a monolithicSparse VMDK.
const vmdkSparseMagic = 0x564d444b

// Descriptor size caps: reject an absurd embedded descriptor, and bound the
// plain-text fallback scan.
const (
	maxDescriptorBytes = 1 << 20 // 1 MiB is far more than any real VMDK descriptor
	maxScanBytes       = 1 << 20 // bound for the plain-descriptor fallback scan
)

// IsVMDK reports whether the file at path is a VMDK — either a monolithicSparse
// image (sparse extent header magic) or a plain-text VMDK descriptor. It is used
// by the import path to route a VMDK through content validation BEFORE handing it
// to qemu-img, so a hostile descriptor (which qemu-img may refuse to even open
// because it points at a missing parent/extent) is still rejected with a clear
// "not self-contained" error rather than an opaque qemu-img failure.
func IsVMDK(path string) (bool, error) {
	desc, err := readVMDKDescriptor(path)
	if err != nil {
		return false, err
	}
	return desc != "", nil
}

// ValidateSelfContainedVMDK rejects a VMDK that is not a self-contained,
// standalone disk. It defends the import path: a hostile descriptor could point
// the disk at an attacker-chosen parent or at host files via an absolute/escaping
// extent path, which the hypervisor would then read at boot.
//
// It rejects a descriptor that:
//   - names a parent (parentFileNameHint, or parentCID other than the "no parent"
//     sentinel ffffffff) — i.e. a child/linked disk, or
//   - has an extent whose backing filename is absolute or escapes the directory
//     containing the VMDK (path traversal).
//
// The descriptor is read from the sparse extent header when present (embedded,
// monolithicSparse) and otherwise by scanning a bounded prefix (a plain-text
// descriptor file). A file with no recognizable descriptor is accepted here; the
// caller's content-based format/backing-file checks cover the other formats. This
// function only tightens VMDKs.
func ValidateSelfContainedVMDK(path string) error {
	desc, err := readVMDKDescriptor(path)
	if err != nil {
		return err
	}
	if desc == "" {
		return nil
	}
	return validateVMDKDescriptor(desc, filepath.Dir(path))
}

// ValidateImportVMDK is the shared self-containment guard for an untrusted disk
// image on an import path. It routes by CONTENT, not filename: a non-VMDK input
// returns nil (the caller's content-based format/backing-file checks cover those
// formats), while a VMDK is validated by ValidateSelfContainedVMDK and, if it
// names a parent or uses an absolute/escaping extent path, rejected with an
// errhint.ErrHint carrying a flatten hint.
//
// Running this BEFORE qemu-img matters: a hostile descriptor points at a missing
// parent/extent that qemu-img refuses to even open, so relying on qemu-img would
// surface an opaque failure instead of this clear "not self-contained" rejection.
func ValidateImportVMDK(path string) error {
	isVMDK, err := IsVMDK(path)
	if err != nil {
		return fmt.Errorf("failed to inspect import image: %w", err)
	}
	if !isVMDK {
		return nil
	}
	if err := ValidateSelfContainedVMDK(path); err != nil {
		return &errhint.ErrHint{
			Err:  fmt.Errorf("import vmdk is not self-contained: %w", err),
			Hint: "flatten the image first: qemu-img convert -O qcow2 <src> <flat.qcow2>",
		}
	}
	return nil
}

// InspectImportSource validates that the untrusted disk image at src is a
// self-contained image safe to convert, and returns the content-detected source
// format qemu-img should convert FROM ("vmdk", "qcow2", "raw", …). It is the
// single source of truth for import-source validation shared by the base-image
// import command and the VMware backend disk import, so the two paths cannot
// drift apart on which images they accept.
//
// A VMDK is validated by ValidateImportVMDK (no parent, no absolute/escaping
// extent) BEFORE qemu-img is invoked, so a hostile descriptor is rejected with a
// clear "not self-contained" error rather than an opaque qemu-img failure. A
// non-VMDK is content-detected via qemu-img and rejected if it carries a
// backing-file pointer.
func InspectImportSource(ctx context.Context, src string) (string, error) {
	isVMDK, err := IsVMDK(src)
	if err != nil {
		return "", fmt.Errorf("failed to inspect import image: %w", err)
	}
	if isVMDK {
		if err := ValidateImportVMDK(src); err != nil {
			return "", err
		}
		return formatVMDK, nil
	}

	format, err := qemuimg.Format(ctx, src)
	if err != nil {
		return "", fmt.Errorf("failed to inspect import image: %w", err)
	}
	// Defensive invariant: IsVMDK recognizes every PLAIN-TEXT descriptor qemu-img's
	// probe does (see looksLikePlainVMDKDescriptor). The residual sparse gaps
	// (COWD/VMDK3 magic, or a descriptor abox cannot read) are NOT covered, so a
	// "vmdk" here means the two detectors disagreed on such a case — refuse rather
	// than convert an un-validated VMDK.
	if format == formatVMDK {
		return "", &errhint.ErrHint{
			Err:  errors.New("unrecognized or unsupported VMDK descriptor"),
			Hint: "flatten the image first: qemu-img convert -O qcow2 <src> <flat.qcow2>",
		}
	}
	if err := qemuimg.RejectBackingFile(ctx, src,
		"an imported image must be self-contained",
		"flatten the image first: qemu-img convert -O qcow2 <src> <flat.qcow2>"); err != nil {
		return "", err
	}
	return format, nil
}

// readVMDKDescriptor returns the descriptor text of the VMDK at path, or "" if
// none is found. For a monolithicSparse VMDK it reads the embedded descriptor
// located by the sparse header; otherwise it returns a bounded plain-text prefix
// so a standalone descriptor file is still validated.
func readVMDKDescriptor(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open vmdk: %w", err)
	}
	defer f.Close()

	// Sparse extent header: magic(4) version(4) flags(4) capacity(8)
	// grainSize(8) descriptorOffset(8, sectors) descriptorSize(8, sectors) ...
	var hdr [44]byte
	n, _ := io.ReadFull(f, hdr[:])
	if n >= 44 && binary.LittleEndian.Uint32(hdr[0:4]) == vmdkSparseMagic {
		return readSparseDescriptor(f, hdr)
	}

	// Not a sparse extent header. It may be a plain-text descriptor file. Read a
	// bounded prefix and check for the descriptor signature.
	//
	// Detection must be a SUPERSET of qemu-img's own vmdk probe: any file qemu-img
	// would open as a VMDK (and thus read extents from) must be routed through
	// self-containment validation here. See looksLikePlainVMDKDescriptor.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("failed to rewind vmdk: %w", err)
	}
	prefix, err := io.ReadAll(io.LimitReader(f, maxScanBytes))
	if err != nil {
		return "", fmt.Errorf("failed to read vmdk: %w", err)
	}
	if looksLikePlainVMDKDescriptor(prefix) {
		return string(prefix), nil
	}
	return "", nil
}

// plainVMDKToken is what qemu-img's vmdk_probe requires at the start of a
// plain-text descriptor, after skipping comments and whitespace.
var plainVMDKToken = []byte("version")

// looksLikePlainVMDKDescriptor reports whether b begins a plain-text VMDK
// descriptor. It is a strict superset of qemu-img's vmdk_probe: skip leading
// comment lines (#...\n) and ALL whitespace (' ', '\t', '\r', '\n', including
// blank lines), then require the "version" token. Being a superset guarantees
// abox recognizes every plain-text descriptor qemu-img would read as a VMDK; the
// only cost of over-detection is a possible false-positive rejection, never a
// bypass. A genuine "# Disk DescriptorFile" header is just a comment line the
// loop skips before reaching the "version" line, so it is still detected.
//
// A qcow2 ("QFI\xfb…") or raw image whose body merely contains "version" is not
// misclassified: its first byte is neither '#' nor whitespace, so the loop hits
// default at offset 0 where the format magic (not "version") sits — matching
// qemu-img, which also probes from offset 0.
//
// A raw byte scan (not bufio.Scanner) is used deliberately: Scanner's 64 KiB line
// cap would error on a pathological long first line and break the superset
// guarantee.
func looksLikePlainVMDKDescriptor(b []byte) bool {
	for len(b) > 0 {
		switch b[0] {
		case '#': // skip a comment line
			nl := bytes.IndexByte(b, '\n')
			if nl < 0 {
				return false
			}
			b = b[nl+1:]
		case ' ', '\t', '\r', '\n': // skip whitespace, including blank lines
			b = b[1:]
		default:
			return bytes.HasPrefix(b, plainVMDKToken)
		}
	}
	return false
}

// readSparseDescriptor reads the embedded descriptor of a monolithicSparse VMDK,
// located by the (already-validated) sparse extent header hdr. It returns "" when
// the header does not point at a plausible, in-bounds descriptor so a hostile
// header degrades to "no descriptor" rather than an error or a bad read.
func readSparseDescriptor(f *os.File, hdr [44]byte) (string, error) {
	offSectors := binary.LittleEndian.Uint64(hdr[28:36])
	sizeSectors := binary.LittleEndian.Uint64(hdr[36:44])
	// Guard the *512 conversion against uint64 overflow before applying the cap
	// (mirrors the offset guard below): maxDescriptorBytes is a multiple of 512, so
	// sizeSectors > maxDescriptorBytes/512 is equivalent to byteSize >
	// maxDescriptorBytes but cannot wrap. A zero size or one past the cap (including
	// a value that would wrap) means no plausible descriptor — treat it as absent.
	if sizeSectors == 0 || sizeSectors > maxDescriptorBytes/512 {
		return "", nil
	}
	byteSize := sizeSectors * 512
	// descriptorOffset is attacker-controllable. Guard the byte conversion against
	// overflow, then require the offset to land inside the file. An out-of-range
	// offset means no trustworthy embedded descriptor — treat it as absent rather
	// than seeking to a wrapped/negative position.
	if offSectors > math.MaxInt64/512 {
		return "", nil
	}
	off := int64(offSectors * 512)
	fi, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to stat vmdk: %w", err)
	}
	if off <= 0 || off >= fi.Size() {
		return "", nil
	}
	// The descriptor must also fit within the file: a header whose size runs past
	// EOF is not a plausible descriptor, so degrade to "absent" rather than erroring
	// on the short read (consistent with every other malformed-header case here).
	if int64(byteSize) > fi.Size()-off {
		return "", nil
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return "", fmt.Errorf("failed to seek to vmdk descriptor: %w", err)
	}
	buf := make([]byte, byteSize)
	if _, err := io.ReadFull(f, buf); err != nil {
		return "", fmt.Errorf("failed to read vmdk descriptor: %w", err)
	}
	// The descriptor is NUL-padded to the sector boundary.
	return string(bytes.TrimRight(buf, "\x00")), nil
}

// validateVMDKDescriptor enforces the self-contained rules on a descriptor's
// text. dir is the directory containing the VMDK, used to bound extent paths.
func validateVMDKDescriptor(desc, dir string) error {
	scanner := bufio.NewScanner(strings.NewReader(desc))
	for scanner.Scan() {
		if err := checkDescriptorLine(strings.TrimSpace(scanner.Text()), dir); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to scan vmdk descriptor: %w", err)
	}
	return nil
}

// checkDescriptorLine enforces the self-contained rules on a single (already
// trimmed) descriptor line. Blank, comment, and unrelated lines are no-ops.
func checkDescriptorLine(line, dir string) error {
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	lower := strings.ToLower(line)

	// Parent pointers: a linked/child disk.
	if strings.HasPrefix(lower, "parentfilenamehint") {
		return errors.New("vmdk names a parent disk (parentFileNameHint); not self-contained")
	}
	if strings.HasPrefix(lower, "parentcid") {
		// "parentCID=ffffffff" is the sentinel for "no parent"; anything else
		// makes this a child disk.
		if v := descriptorValue(line); v != "" && !strings.EqualFold(v, "ffffffff") {
			return fmt.Errorf("vmdk names a parent disk (parentCID=%s); not self-contained", v)
		}
	}

	// Extent lines: e.g. RW 12345 SPARSE "disk-s001.vmdk" or
	// RW 12345 FLAT "/abs/path" 0
	if isExtentLine(lower) {
		name := extentFileName(line)
		if name == "" {
			return nil
		}
		return checkExtentPath(name, dir)
	}
	return nil
}

// isExtentLine reports whether a (lowercased) descriptor line is an extent
// declaration. Extent lines start with an access-mode token.
//
// The line is split on any whitespace run rather than matched against a
// single-space prefix: qemu-img parses extent lines with C sscanf semantics, where
// a format-string space matches any run of spaces/tabs/newlines. Matching only a
// literal single space let a tab-delimited extent (e.g. "RW\t16384\tFLAT\t\"/etc/shadow\"")
// slip past this classifier — so checkExtentPath was never reached — while qemu-img
// still opened the absolute FLAT extent at boot. Tokenizing here keeps the
// classifier a superset of qemu's grammar.
func isExtentLine(lower string) bool {
	fields := strings.Fields(lower)
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "rw", "rdonly", "noaccess":
		return true
	default:
		return false
	}
}

// extentFileName returns the quoted filename in an extent line, or "".
func extentFileName(line string) string {
	i := strings.IndexByte(line, '"')
	if i < 0 {
		return ""
	}
	j := strings.IndexByte(line[i+1:], '"')
	if j < 0 {
		return ""
	}
	return line[i+1 : i+1+j]
}

// descriptorValue returns the value after '=' in a key=value descriptor line,
// trimmed of surrounding whitespace and quotes.
func descriptorValue(line string) string {
	_, v, ok := strings.Cut(line, "=")
	if !ok {
		return ""
	}
	return strings.Trim(strings.TrimSpace(v), `"`)
}

// checkExtentPath rejects an extent backing path that is absolute or escapes the
// VMDK's own directory (path traversal). A bare filename (the self-contained
// case) is accepted.
func checkExtentPath(name, dir string) error {
	if filepath.IsAbs(name) {
		return fmt.Errorf("vmdk extent path is absolute (%q); not self-contained", name)
	}
	// filepath.IsAbs is platform-dependent: a POSIX-absolute path ("/etc/shadow")
	// is not absolute on Windows. The descriptor is portable text authored on any
	// host, so reject a leading-slash path explicitly regardless of GOOS.
	if strings.HasPrefix(name, "/") {
		return fmt.Errorf("vmdk extent path is absolute (%q); not self-contained", name)
	}
	// Reject a Windows-style absolute path (e.g. C:\...) too: the descriptor is
	// portable text and must not resolve outside dir on any host.
	if len(name) >= 2 && name[1] == ':' {
		return fmt.Errorf("vmdk extent path is absolute (%q); not self-contained", name)
	}
	// Reject a backslash-rooted path (\foo) as well.
	if strings.HasPrefix(name, `\`) {
		return fmt.Errorf("vmdk extent path is absolute (%q); not self-contained", name)
	}
	// Normalize slashes then resolve against the VMDK's directory; ensure it stays
	// within it.
	clean := filepath.Clean(filepath.Join(dir, filepath.FromSlash(strings.ReplaceAll(name, `\`, "/"))))
	rel, err := filepath.Rel(dir, clean)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("vmdk extent path escapes the image directory (%q); not self-contained", name)
	}
	return nil
}
