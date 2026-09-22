package serve

import (
	"path/filepath"
	"testing"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/filterbase"
	"github.com/sandialabs/abox/internal/httpfilter"
	"github.com/sandialabs/abox/internal/secretstore"
)

// findRule returns the resolved rule for a host, or false.
func findRule(rules []httpfilter.SecretRule, host string) (httpfilter.SecretRule, bool) {
	for _, r := range rules {
		if r.Host == host {
			return r, true
		}
	}
	return httpfilter.SecretRule{}, false
}

func TestResolveSecretRules_ValuePrefixConcat(t *testing.T) {
	bindings := []config.SecretInjection{
		{Key: "t", Host: "api.example.com", Header: "Authorization", ValuePrefix: "Bearer "},
	}
	rules := resolveSecretRules("box", bindings, map[string]string{"t": "tok"})
	r, ok := findRule(rules, "api.example.com")
	if !ok || r.Strip {
		t.Fatalf("expected an inject rule, got %+v (ok=%v)", r, ok)
	}
	if r.Value != "Bearer tok" {
		t.Errorf("value = %q, want %q (prefix must precede the stored value)", r.Value, "Bearer tok")
	}
}

func TestResolveSecretRules_MissingValueBecomesStrip(t *testing.T) {
	bindings := []config.SecretInjection{
		{Key: "absent", Host: "api.example.com", Header: "x-api-key", PathPrefix: "/v1/"},
	}
	rules := resolveSecretRules("box", bindings, map[string]string{})
	r, ok := findRule(rules, "api.example.com")
	if !ok || !r.Strip {
		t.Fatalf("missing value must become a strip rule, got %+v (ok=%v)", r, ok)
	}
	if r.Value != "" {
		t.Errorf("strip rule must have empty value, got %q", r.Value)
	}
	if r.PathPrefix != "/v1/" {
		t.Errorf("strip rule must carry path_prefix, got %q", r.PathPrefix)
	}
}

func TestResolveSecretRules_InvalidValueBecomesStrip(t *testing.T) {
	bindings := []config.SecretInjection{
		{Key: "t", Host: "api.example.com", Header: "x-api-key"},
	}
	// A stored value with an embedded newline would break the request / enable
	// smuggling — must degrade to strip, never inject.
	rules := resolveSecretRules("box", bindings, map[string]string{"t": "line1\nInjected: evil"})
	r, ok := findRule(rules, "api.example.com")
	if !ok || !r.Strip {
		t.Fatalf("invalid header value must become a strip rule, got %+v (ok=%v)", r, ok)
	}
}

func TestApplySecretInjections_FailsClosed(t *testing.T) {
	newSetup := func(mitm bool) *filterbase.DaemonSetup {
		paths, err := config.GetPaths("nonexistent-test-instance")
		if err != nil {
			t.Fatalf("GetPaths: %v", err)
		}
		// point the store at a temp path so no real instance is touched
		paths.Secrets = filepath.Join(t.TempDir(), "secrets")
		return &filterbase.DaemonSetup{
			Inst: &config.Instance{
				HTTP: config.HTTPConfig{
					MITM: mitm,
					SecretInjections: []config.SecretInjection{
						{Key: "k", Host: "api.example.com", Header: "x-api-key"},
					},
				},
			},
			Paths: paths,
		}
	}

	// MITM disabled → must refuse.
	srv := httpfilter.NewServer(allowlist.NewFilter(), false)
	if err := applySecretInjections(srv, newSetup(false), false, "box"); err == nil {
		t.Error("expected error when MITM is disabled with injections configured")
	}

	// Passive mode → must refuse.
	srv2 := httpfilter.NewServer(allowlist.NewFilter(), true)
	if err := applySecretInjections(srv2, newSetup(true), true, "box"); err == nil {
		t.Error("expected error in passive mode with injections configured")
	}
}

func TestApplySecretInjections_NoBindingsIsNoop(t *testing.T) {
	paths, _ := config.GetPaths("nonexistent-test-instance")
	paths.Secrets = filepath.Join(t.TempDir(), "secrets")
	setup := &filterbase.DaemonSetup{
		Inst:  &config.Instance{HTTP: config.HTTPConfig{MITM: true}},
		Paths: paths,
	}
	srv := httpfilter.NewServer(allowlist.NewFilter(), false)
	if err := applySecretInjections(srv, setup, false, "box"); err != nil {
		t.Errorf("no bindings should be a no-op, got %v", err)
	}
}

// TestApplySecretInjections_EndToEnd exercises the real store → resolve → install
// path, and confirms a missing key degrades to strip.
func TestApplySecretInjections_EndToEnd(t *testing.T) {
	paths, _ := config.GetPaths("nonexistent-test-instance")
	paths.Secrets = filepath.Join(t.TempDir(), "secrets")
	if err := secretstore.New(paths.Secrets).Set("present", "sk-123"); err != nil {
		t.Fatal(err)
	}
	setup := &filterbase.DaemonSetup{
		Inst: &config.Instance{HTTP: config.HTTPConfig{
			MITM: true,
			SecretInjections: []config.SecretInjection{
				{Key: "present", Host: "api.present.com", Header: "x-api-key"},
				{Key: "absent", Host: "api.absent.com", Header: "x-api-key"},
			},
		}},
		Paths: paths,
	}
	srv := httpfilter.NewServer(allowlist.NewFilter(), false)
	if err := applySecretInjections(srv, setup, false, "box"); err != nil {
		t.Fatalf("applySecretInjections: %v", err)
	}
	// No panic / error is the primary assertion; rule-level behavior is covered by
	// resolveSecretRules tests and the httpfilter inject tests.
}
