//go:build darwin

package dnsfilter

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func withScutil(t *testing.T, out string, err error) {
	t.Helper()
	prev := scutilCommand
	scutilCommand = func() ([]byte, error) { return []byte(out), err }
	t.Cleanup(func() { scutilCommand = prev })
}

func TestScutilUpstream_FirstIPv4(t *testing.T) {
	// Representative `scutil --dns` output: the primary resolver (#1) lists an
	// IPv6 then an IPv4 nameserver; we take the first IPv4 as "ip:53".
	out := `DNS configuration

resolver #1
  search domain[0] : corp.example
  nameserver[0] : fe80::1
  nameserver[1] : 10.0.0.53
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  nameserver[0] : 192.0.2.54
`
	withScutil(t, out, nil)
	got, ok := scutilUpstream()
	if !ok {
		t.Fatal("scutilUpstream should succeed on valid output")
	}
	if got != "10.0.0.53:53" {
		t.Errorf("upstream = %q, want %q", got, "10.0.0.53:53")
	}
}

func TestScutilUpstream_NoNameserver(t *testing.T) {
	withScutil(t, "DNS configuration\n\nresolver #1\n  flags : Request A records\n", nil)
	if _, ok := scutilUpstream(); ok {
		t.Error("scutilUpstream should fail when no nameserver is present")
	}
}

func TestScutilUpstream_CommandError(t *testing.T) {
	withScutil(t, "", errors.New("boom"))
	if _, ok := scutilUpstream(); ok {
		t.Error("scutilUpstream should fail when scutil errors")
	}
}

func TestDarwinSystemUpstream_FallsBackToResolvConf(t *testing.T) {
	// scutil yields nothing → fall back to the resolv.conf reader.
	withScutil(t, "", errors.New("no scutil"))
	origPath := resolvConfPath
	t.Cleanup(func() { resolvConfPath = origPath })

	f := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(f, []byte("nameserver 192.0.2.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resolvConfPath = f

	got, ok := darwinSystemUpstream()
	if !ok {
		t.Fatal("darwinSystemUpstream should fall back to resolv.conf")
	}
	if got != "192.0.2.53:53" {
		t.Errorf("upstream = %q, want %q", got, "192.0.2.53:53")
	}
}
