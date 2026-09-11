// Package qemuimg wraps the qemu-img CLI for the disk operations abox needs.
// It centralizes the invocations so they are defined once and reused across the
// backend, base-image, and migrate code paths.
package qemuimg

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/sandialabs/abox/internal/errhint"
)

// Format names passed to qemu-img's -f/-O flags. formatQCOW2 is abox's canonical
// disk format, used as both the -f source and -O output/-F backing format across
// builders. formatRaw/formatVMDK name the vfkit and VMware output formats.
const (
	formatQCOW2 = "qcow2"
	formatRaw   = "raw"
	formatVMDK  = "vmdk"
)

// subformatMonolithicSparse is qemu-img's default VMDK subformat: a single,
// growable .vmdk (no split extents, no separate descriptor) that VMware
// Workstation and Fusion open directly. Pinned explicitly for reproducibility.
const subformatMonolithicSparse = "monolithicSparse"

// cmdConvert is the qemu-img subcommand and the default error label for the
// convert core (see convert).
const cmdConvert = "convert"

// info is the subset of `qemu-img info --output=json` that abox consumes.
//
// FormatSpecific carries the qcow2 external data file (format-specific.data.data-file):
// an independent host-path reference, orthogonal to the backing chain, that points
// the image's actual guest data at another file. A self-contained import image must
// not carry one (see RejectExternalReferences) — the guard reads it from qemu's own
// parse rather than re-implementing the qcow2 header, so it cannot be evaded by a
// field abox does not know how to parse.
type info struct {
	Format          string          `json:"format"`
	BackingFilename string          `json:"backing-filename"`
	FormatSpecific  *formatSpecific `json:"format-specific"`
}

// formatSpecific is the format-specific.data subtree of `qemu-img info`. Only the
// qcow2 external data file is consumed today (see info).
type formatSpecific struct {
	Data struct {
		DataFile string `json:"data-file"`
	} `json:"data"`
}

// dataFile returns the qcow2 external data-file pointer, or "" if the image has
// none (the common, self-contained case).
func (i info) dataFile() string {
	if i.FormatSpecific == nil {
		return ""
	}
	return i.FormatSpecific.Data.DataFile
}

// runCmd builds the qemu-img command. A package var so tests can capture the
// argument vector (e.g. to assert the "--" end-of-options separator precedes the
// trailing path positionals) without running qemu-img.
var runCmd = exec.CommandContext

// SetRunCmdForTest replaces the qemu-img command builder and returns a restore
// func. It lets callers in other packages stub qemu-img hermetically (e.g. to
// control the reported backing-filename) without invoking the real binary,
// mirroring vmrun.SetRunCommandForTest. Test-only helper.
func SetRunCmdForTest(fn func(ctx context.Context, name string, args ...string) *exec.Cmd) func() {
	prev := runCmd
	runCmd = fn
	return func() { runCmd = prev }
}

// info runs `qemu-img info --output=json -- <path>` and returns the parsed
// subset abox consumes. The "--" end-of-options separator precedes the path
// positional (see TestBuildersInsertDoubleDash), and the runCmd seam lets tests
// capture the argument vector without invoking qemu-img.
func infoOf(ctx context.Context, path string) (info, error) {
	out, err := runCmd(ctx, "qemu-img", "info", "--output=json", "--", path).Output()
	if err != nil {
		return info{}, fmt.Errorf("qemu-img info failed: %w", err)
	}
	var i info
	if err := json.Unmarshal(out, &i); err != nil {
		return info{}, fmt.Errorf("failed to parse qemu-img info: %w", err)
	}
	return i, nil
}

// Format returns the disk format qemu-img detects for the image at path (e.g.
// "qcow2", "vmdk", "raw"). Detection is by CONTENT, not filename, so a qcow2
// named ".img" or ".vmdk" is still reported as qcow2 — callers must use this
// rather than the file extension for any security-relevant decision.
func Format(ctx context.Context, path string) (string, error) {
	i, err := infoOf(ctx, path)
	if err != nil {
		return "", err
	}
	return i.Format, nil
}

// BackingFile returns the backing-file path embedded in the qcow2 image at path,
// or "" if it has none. An error is returned only when qemu-img itself fails.
func BackingFile(ctx context.Context, path string) (string, error) {
	i, err := infoOf(ctx, path)
	if err != nil {
		return "", err
	}
	return i.BackingFilename, nil
}

// Rebase repoints a CoW disk's backing file to backingFile without touching data
// (an unsafe rebase: the backing image is byte-identical, just relocated).
func Rebase(ctx context.Context, disk, backingFile string) error {
	cmd := runCmd(ctx, "qemu-img", "rebase", "-u", "-b", backingFile, "-F", formatQCOW2, "--", disk)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img rebase failed: %s: %w", string(out), err)
	}
	return nil
}

// Check validates that the disk at path opens together with its full backing
// chain, erroring if any link in that chain is missing or cannot be opened. It is
// used after an unsafe rebase (see Rebase), which only rewrites the backing
// pointer without validating that the new backing file actually exists and opens,
// to confirm the resulting chain is intact.
//
// It runs `qemu-img info --backing-chain` rather than `qemu-img check`:
// --backing-chain opens every link in the chain (plain `qemu-img info` opens only
// the top image and returns success even when the backing file is missing), while
// avoiding the full consistency scan that `qemu-img check` performs — that scan
// flags benign leaked clusters (exit 3) common in normal qcow2 overlays and would
// produce false failures. A non-zero exit is the only signal we need, so the JSON
// output is not parsed. The "--" end-of-options separator precedes the path
// positional, and the runCmd seam lets tests capture the argument vector.
func Check(ctx context.Context, path string) error {
	cmd := runCmd(ctx, "qemu-img", "info", "--backing-chain", "--output=json", "--", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img info failed: %s: %w", string(out), err)
	}
	return nil
}

// Create creates a copy-on-write qcow2 disk at output backed (read-only) by
// backingFile and sized to size (e.g. "20G").
func Create(ctx context.Context, backingFile, output, size string) error {
	cmd := runCmd(ctx, "qemu-img", "create",
		"-f", formatQCOW2,
		"-F", formatQCOW2,
		"-b", backingFile,
		"--",
		output,
		size,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img create failed: %s: %w", string(out), err)
	}
	return nil
}

// convertOpts drives the single `qemu-img convert` core (see convert). Every
// public Convert* wrapper is a thin shim that fills these in, so the flag order
// and the "--" end-of-options separator are defined once.
type convertOpts struct {
	// src, dst are the source and destination path positionals (placed after "--").
	src, dst string
	// srcFormat is the -f source format. Omitted when "", letting qemu-img probe
	// the source (used by the VMDK flatten paths, which must resolve the on-disk
	// descriptor). Callers that have already content-detected an untrusted format
	// pass it explicitly so qemu-img does not re-probe.
	srcFormat string
	// dstFormat is the -O output format. Required.
	dstFormat string
	// subformat is the -o subformat=<...> value. Omitted when "".
	subformat string
	// compress adds -c (compressed output).
	compress bool
	// label names the operation in the error message ("qemu-img <label> failed:").
	label string
}

// convert is the single home for `qemu-img convert`. It assembles the flags from
// opts in a fixed order — [-c] [-f srcFormat] -O dstFormat [-o subformat=...] --
// src dst — always inserting the "--" end-of-options separator before the path
// positionals (see TestBuildersInsertDoubleDash) and always flowing through the
// runCmd seam so tests can capture the argv without invoking qemu-img.
func convert(ctx context.Context, opts convertOpts) error {
	args := []string{cmdConvert}
	if opts.compress {
		args = append(args, "-c")
	}
	if opts.srcFormat != "" {
		args = append(args, "-f", opts.srcFormat)
	}
	args = append(args, "-O", opts.dstFormat)
	if opts.subformat != "" {
		args = append(args, "-o", "subformat="+opts.subformat)
	}
	args = append(args, "--", opts.src, opts.dst)
	cmd := runCmd(ctx, "qemu-img", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img %s failed: %s: %w", opts.label, string(out), err)
	}
	return nil
}

// Convert rewrites the qcow2 image at src into a standalone qcow2 at dst, merging
// any backing file so the result is self-contained. When compress is true the
// output is compressed (smaller, slower) — used when flattening a disk for export.
func Convert(ctx context.Context, src, dst string, compress bool) error {
	return convert(ctx, convertOpts{
		src: src, dst: dst,
		srcFormat: formatQCOW2, dstFormat: formatQCOW2,
		compress: compress,
		label:    cmdConvert,
	})
}

// ConvertFrom rewrites the image at src — whose on-disk format is srcFormat
// (e.g. "qcow2", "raw", "vmdk") — into a standalone qcow2 at dst, merging any
// backing file so the result is self-contained. The source format is passed
// explicitly (-f) rather than letting qemu-img probe it, so a caller that has
// already content-detected the format (see Format) does not re-probe untrusted
// input.
func ConvertFrom(ctx context.Context, src, dst, srcFormat string) error {
	return convert(ctx, convertOpts{
		src: src, dst: dst,
		srcFormat: srcFormat, dstFormat: formatQCOW2,
		label: cmdConvert,
	})
}

// ConvertToRaw rewrites the image at src — whose on-disk format is srcFormat —
// into a raw image at dst. Used by the vfkit backend, whose Apple
// Virtualization.framework disks must be raw. The source format is passed
// explicitly (-f) so qemu-img does not re-probe an already content-detected
// input.
func ConvertToRaw(ctx context.Context, src, srcFormat, dst string) error {
	return convert(ctx, convertOpts{
		src: src, dst: dst,
		srcFormat: srcFormat, dstFormat: formatRaw,
		label: "convert to raw",
	})
}

// ConvertToQcow2Compressed rewrites the image at src — whose on-disk format is
// srcFormat — into a compressed, self-contained qcow2 at dst. Used by the vfkit
// backend to export a raw instance disk as a portable archive. The source format
// is passed explicitly (-f) rather than probed.
func ConvertToQcow2Compressed(ctx context.Context, src, srcFormat, dst string) error {
	return convert(ctx, convertOpts{
		src: src, dst: dst,
		srcFormat: srcFormat, dstFormat: formatQCOW2,
		compress: true,
		label:    "convert to qcow2",
	})
}

// ConvertToVMDK converts the qcow2 image at src into a VMDK at dst suitable for
// VMware Workstation/Fusion. This is a full copy: the entire qcow2 (backing chain
// merged) is written out as a standalone VMDK; there is no linked-clone / backing
// relationship between src and dst.
//
// Subformat choice: monolithicSparse. This is qemu-img's default VMDK subformat,
// so it is the most widely-tested output; it produces a single, growable .vmdk
// file (no 2GB split extents, no separate descriptor) that VMware Workstation and
// Fusion open directly. We pass it explicitly rather than relying on the default
// so the format is pinned regardless of the host qemu-img version.
func ConvertToVMDK(ctx context.Context, src, dst string) error {
	return ConvertToVMDKFrom(ctx, src, formatQCOW2, dst)
}

// ConvertToVMDKFrom is ConvertToVMDK with an explicit source format ("qcow2" or
// "raw"). The source format is pinned via -f (never auto-probed) so a hostile
// image cannot trick qemu-img into interpreting itself as a different, more
// dangerous format. Used by the VMware backend, whose base image is qcow2 on
// Linux but raw on macOS (Apple Virtualization.framework writes raw). srcFormat
// must be one of the qemuimg format constants; callers map it from the on-disk
// extension, not from the file's contents.
func ConvertToVMDKFrom(ctx context.Context, src, srcFormat, dst string) error {
	return convert(ctx, convertOpts{
		src: src, dst: dst,
		srcFormat: srcFormat, dstFormat: formatVMDK,
		subformat: subformatMonolithicSparse,
		label:     "convert to vmdk",
	})
}

// FormatForExt maps an on-disk base-image extension (".qcow2" / ".raw") to the
// qemu-img source-format name. Unknown extensions default to qcow2 (abox's
// canonical format). Keeping this mapping here lets callers pin -f from the file
// name without embedding format strings.
func FormatForExt(ext string) string {
	if ext == ".raw" {
		return formatRaw
	}
	return formatQCOW2
}

// FlattenVMDK reads the VMDK disk chain at src (following any parent/backing
// extents) and writes a single self-contained VMDK at dst, using the
// monolithicSparse subformat (see ConvertToVMDK). Used to export a VMware
// instance disk to a portable, standalone image. Unlike Convert it does not read
// the source format explicitly (qemu-img auto-detects the VMDK descriptor),
// which is required so the parent chain is resolved.
func FlattenVMDK(ctx context.Context, src, dst string) error {
	return convert(ctx, convertOpts{
		src: src, dst: dst,
		dstFormat: formatVMDK,
		subformat: subformatMonolithicSparse,
		label:     "convert vmdk to vmdk",
	})
}

// ConvertVMDKToQcow2 reads the VMDK disk chain at src and writes a single
// self-contained qcow2 at dst. Used to export a VMware instance disk to the
// qcow2 format (e.g. for a libvirt import). qemu-img auto-detects the VMDK
// descriptor so the parent chain is resolved into the flat output.
func ConvertVMDKToQcow2(ctx context.Context, src, dst string) error {
	return convert(ctx, convertOpts{
		src: src, dst: dst,
		dstFormat: formatQCOW2,
		label:     "convert vmdk to qcow2",
	})
}

// ConvertVMDKToVMDK rewrites the VMDK at src into a single self-contained
// monolithicSparse VMDK at dst. Used on the UNTRUSTED import path in place of a
// verbatim copy, so no extent reference survives into the stored disk. Unlike
// FlattenVMDK it pins -f vmdk rather than letting qemu-img probe the source: the
// input has already been content-validated as a VMDK (see vmrun.InspectImportSource),
// and re-probing untrusted input reopens the "the format we validated is not the
// format qemu opens" differential.
func ConvertVMDKToVMDK(ctx context.Context, src, dst string) error {
	return convert(ctx, convertOpts{
		src: src, dst: dst,
		srcFormat: formatVMDK, dstFormat: formatVMDK,
		subformat: subformatMonolithicSparse,
		label:     "convert vmdk to vmdk",
	})
}

// ExternalRefOpts controls which external references RejectExternalReferences
// tolerates. A snapshot import legitimately carries a backing-file pointer (the
// caller rebases it onto the local base immediately afterward), so that path sets
// AllowBackingFile; every other external reference — and a backing file on any
// non-snapshot path — is always rejected.
type ExternalRefOpts struct {
	AllowBackingFile bool
}

// RejectExternalReferences inspects the image at path and returns a non-nil ErrHint
// when it references any file other than itself: a backing file (unless
// opts.AllowBackingFile) or a qcow2 external data file. A self-contained import/base
// image must reference nothing external — following an attacker-controlled pointer
// when the disk is opened at boot (by QEMU, possibly as a more-privileged runtime
// user) is the threat this guards.
//
// The external data file (data_file) is an independent host-path reference,
// orthogonal to the backing chain: an image can have no backing file yet point its
// entire data storage at an absolute host path such as /etc/shadow. It is therefore
// rejected even when a backing file is tolerated. Both fields are read from qemu's
// own `qemu-img info` parse, so the check cannot be evaded by whitespace/grammar
// tricks in a field abox does not itself parse.
//
// reason completes the sentence "import image has <ref>; <reason>" and hint supplies
// the CLI remediation text. Returns nil when the image is self-contained, or the
// inspection error when qemu-img itself fails.
func RejectExternalReferences(ctx context.Context, path, reason, hint string, opts ExternalRefOpts) error {
	i, err := infoOf(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to inspect import image: %w", err)
	}
	if i.BackingFilename != "" && !opts.AllowBackingFile {
		return &errhint.ErrHint{
			Err:  fmt.Errorf("import image has a backing file (%s); %s", i.BackingFilename, reason),
			Hint: hint,
		}
	}
	if df := i.dataFile(); df != "" {
		return &errhint.ErrHint{
			Err:  fmt.Errorf("import image has an external data file (%s); %s", df, reason),
			Hint: hint,
		}
	}
	return nil
}

// RejectBackingFile is a thin wrapper over RejectExternalReferences that tolerates
// no external reference at all (no backing file, no external data file). Retained
// for the existing non-snapshot call sites.
func RejectBackingFile(ctx context.Context, path, reason, hint string) error {
	return RejectExternalReferences(ctx, path, reason, hint, ExternalRefOpts{})
}
