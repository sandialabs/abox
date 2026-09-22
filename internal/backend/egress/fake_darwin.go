//go:build darwin

package egress

import (
	"context"

	"github.com/sandialabs/abox/internal/backend"
)

// FakeEnforcer is a test double for backend.PfEnforcer that records calls so
// tests can assert which instance/subnet/rules a controller passes through,
// without touching pfctl or a privilege helper.
//
// It lives in a normal (non-_test.go) file so it can be shared across the pf
// backends' test suites (vfkit, vmware) and this package's own tests — matching
// the internal/backend/conformance model of an exported, importable test helper.
// Go cannot import symbols from another package's _test.go files, so a shared
// fake must be exported from a regular file.
type FakeEnforcer struct {
	EnableCalled bool
	LoadCalled   bool
	LoadInstance string
	LoadSubnet   string
	LoadRules    string
	FlushCalled  bool
	FlushName    string
	EnableErr    error
	LoadErr      error
}

func (f *FakeEnforcer) Enable(ctx context.Context) error {
	f.EnableCalled = true
	return f.EnableErr
}

func (f *FakeEnforcer) LoadAnchor(ctx context.Context, instance, subnet, rules string) error {
	f.LoadCalled = true
	f.LoadInstance = instance
	f.LoadSubnet = subnet
	f.LoadRules = rules
	return f.LoadErr
}

func (f *FakeEnforcer) FlushAnchor(ctx context.Context, instance string) error {
	f.FlushCalled = true
	f.FlushName = instance
	return nil
}

func (f *FakeEnforcer) TeardownConfig(ctx context.Context) error { return nil }

// StaticProvider returns a backend.PfEnforcerProvider that always yields enf. It
// is the convenience wiring tests use to inject a FakeEnforcer into a PfBase.
func StaticProvider(enf backend.PfEnforcer) backend.PfEnforcerProvider {
	return func() (backend.PfEnforcer, error) { return enf, nil }
}
