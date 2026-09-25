package cmdutil

import (
	"errors"
	"fmt"

	"github.com/sandialabs/abox/internal/boxfile"
	"github.com/sandialabs/abox/internal/iostreams"
)

// TrustBoxfile enforces the first-use trust gate for a repo-supplied abox.yaml.
// It must be called AFTER the boxfile is parsed and validated but BEFORE any
// security-relevant value is acted on (including --dry-run and any sudo/privilege
// prompt), so a hostile abox.yaml cannot silently downgrade the sandbox.
//
// Behavior:
//   - No security-relevant settings => returns nil silently (no friction).
//   - Already trusted at this exact fingerprint => returns nil.
//   - trustToken matches the fingerprint (from --trust-boxfile / ABOX_TRUST_BOXFILE)
//     => trusts and returns nil (the scripted/CI opt-in).
//   - Interactive TTY with a Prompter => prints the summary and asks to confirm;
//     on yes, records trust and returns nil; on no, returns an error.
//   - Otherwise (non-interactive, untrusted) => fails CLOSED with guidance.
//
// rawYAML must be the exact bytes parsed into box (see boxfile.LoadRaw) so the
// fingerprint attests to what will actually be used.
func TrustBoxfile(io *iostreams.IOStreams, prompter Prompter, cs *ColorScheme, box *boxfile.Boxfile, rawYAML []byte, boxDir, trustToken string) error {
	summary := boxfile.SecuritySummary(box)
	if len(summary) == 0 {
		return nil
	}

	fingerprint := boxfile.TrustFingerprint(box, rawYAML, boxDir)

	trusted, err := boxfile.IsTrusted(boxDir, fingerprint)
	if err != nil {
		return fmt.Errorf("checking abox.yaml trust: %w", err)
	}
	if trusted {
		return nil
	}

	// Scripted opt-in: an externally-supplied expected fingerprint.
	if trustToken != "" && trustToken == fingerprint {
		return boxfile.MarkTrusted(boxDir, fingerprint)
	}

	printSecuritySummary(io, cs, boxDir, summary, fingerprint)

	if io.IsTerminal() && prompter != nil {
		if prompter.Confirm("Trust and apply these security-relevant settings from abox.yaml? ") {
			return boxfile.MarkTrusted(boxDir, fingerprint)
		}
		return errors.New("abox.yaml declined; its security-relevant settings were not applied")
	}

	// Non-interactive and untrusted: fail closed.
	return fmt.Errorf("abox.yaml in %s sets security-relevant options and has not been trusted; "+
		"run once interactively to review and confirm, or pass --trust-boxfile=%s "+
		"(or ABOX_TRUST_BOXFILE=%s) after reviewing", boxDir, fingerprint, fingerprint)
}

func printSecuritySummary(io *iostreams.IOStreams, cs *ColorScheme, boxDir string, summary []string, fingerprint string) {
	w := io.ErrOut
	fmt.Fprintln(w)
	fmt.Fprintln(w, cs.Yellow(cs.Bold("This abox.yaml requests security-relevant settings:")))
	fmt.Fprintf(w, cs.Yellow("  (from %s)\n"), boxDir)
	for _, line := range summary {
		fmt.Fprintf(w, cs.Yellow("  - %s\n"), line)
	}
	fmt.Fprintln(w, cs.Yellow("Only trust this if you understand and accept these settings."))
	fmt.Fprintf(w, cs.Yellow("  fingerprint: %s\n"), fingerprint)
	fmt.Fprintln(w)
}
