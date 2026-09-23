package boxfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/config"
)

func TestSecuritySummary_Empty(t *testing.T) {
	b := DefaultBoxfile()
	if s := SecuritySummary(b); len(s) != 0 {
		t.Errorf("default boxfile should have empty security summary, got %v", s)
	}
}

func TestSecuritySummary_FlagsEachKey(t *testing.T) {
	b := DefaultBoxfile()
	b.Provision = []string{"/etc/setup.sh", "relative.sh"}
	b.Overlay = "/home/user/.ssh"
	b.Monitor.Policies = []string{"/abs/policy.yaml"}
	b.HTTP.AllowPrivateTargets = []string{"127.0.0.0/8"}
	b.HTTP.MITM = new(bool) // false
	b.HTTP.AllowedPorts = []int{22, 3389}
	b.HTTP.SecretInjections = []config.SecretInjection{{Key: "api", Host: "attacker.example.com", Header: "Authorization"}}
	b.DNS.Upstream = "9.9.9.9:53"
	b.Overrides = map[string]map[string]string{"libvirt": {"template": "custom.xml"}}

	got := SecuritySummary(b)
	joined := ""
	for _, s := range got {
		joined += s + "\n"
	}
	for _, want := range []string{
		"/etc/setup.sh", ".ssh", "/abs/policy.yaml", "127.0.0.0/8",
		"mitm: false", "allowed_ports", "custom", "template",
		"secret_injections", "attacker.example.com", "dns.upstream", "9.9.9.9:53",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("summary missing %q; got:\n%s", want, joined)
		}
	}
	// A relative provision path is NOT flagged.
	if strings.Contains(joined, "relative.sh") {
		t.Errorf("relative path should not be flagged; got:\n%s", joined)
	}
}

// TestSecuritySummary_SecretInjectionsAloneFlagged ensures a boxfile whose ONLY
// security-relevant setting is a secret-injection binding still triggers the
// trust gate (regression: this key was previously missed, silently bypassing it).
func TestSecuritySummary_SecretInjectionsAloneFlagged(t *testing.T) {
	b := DefaultBoxfile()
	b.HTTP.SecretInjections = []config.SecretInjection{{Key: "api", Host: "evil.example.com", Header: "X-Api-Key"}}
	if len(SecuritySummary(b)) == 0 {
		t.Error("a secret_injections binding must be flagged as security-relevant")
	}
}

// TestSecuritySummary_DNSUpstreamAloneFlagged ensures a custom upstream DNS alone
// triggers the trust gate.
func TestSecuritySummary_DNSUpstreamAloneFlagged(t *testing.T) {
	b := DefaultBoxfile()
	b.DNS.Upstream = "9.9.9.9:53"
	if len(SecuritySummary(b)) == 0 {
		t.Error("a custom dns.upstream must be flagged as security-relevant")
	}
}

// TestTrustFingerprint_ChangesOnYAMLEdit and _ChangesOnReferencedFileEdit lock in
// that the fingerprint covers both the yaml bytes and referenced host-side
// file contents.
func TestTrustFingerprint_ChangesOnYAMLEdit(t *testing.T) {
	b := DefaultBoxfile()
	fp1 := TrustFingerprint(b, []byte("version: 1\n"), t.TempDir())
	fp2 := TrustFingerprint(b, []byte("version: 1\ncpus: 4\n"), t.TempDir())
	if fp1 == fp2 {
		t.Error("fingerprint must change when the yaml bytes change")
	}
}

func TestTrustFingerprint_ChangesOnReferencedTemplateEdit(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "custom.xml")
	if err := os.WriteFile(tmpl, []byte("<domain>v1</domain>"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := DefaultBoxfile()
	b.Overrides = map[string]map[string]string{"libvirt": {"template": "custom.xml"}}
	raw := []byte("version: 1\n")

	fp1 := TrustFingerprint(b, raw, dir)

	// Swap the referenced template's content; the yaml is untouched.
	if err := os.WriteFile(tmpl, []byte("<domain>EVIL</domain>"), 0o600); err != nil {
		t.Fatal(err)
	}
	fp2 := TrustFingerprint(b, raw, dir)
	if fp1 == fp2 {
		t.Error("fingerprint must change when a referenced template file changes (swap-after-trust attack)")
	}
}

// TestIsTrusted_RequiresFingerprintEquality locks in that trusting a path at one
// fingerprint must NOT auto-trust a different fingerprint at the same path.
func TestIsTrusted_RequiresFingerprintEquality(t *testing.T) {
	// Redirect the trust cache into a temp XDG_DATA_HOME.
	tmp := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tmp)

	dir := "/some/repo"
	if err := MarkTrusted(dir, "fingerprintA"); err != nil {
		t.Fatalf("MarkTrusted: %v", err)
	}

	okSame, err := IsTrusted(dir, "fingerprintA")
	if err != nil {
		t.Fatal(err)
	}
	if !okSame {
		t.Error("same path + same fingerprint should be trusted")
	}

	okDiff, err := IsTrusted(dir, "fingerprintB")
	if err != nil {
		t.Fatal(err)
	}
	if okDiff {
		t.Error("same path + DIFFERENT fingerprint must NOT be trusted (path-reuse attack)")
	}
}

func TestMarkTrusted_FilePerms0600(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tmp)
	if err := MarkTrusted("/repo", "fp"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(tmp, "abox", "trusted-boxfiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("trust cache perms = %o, want 600", fi.Mode().Perm())
	}
}
