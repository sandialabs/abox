//go:build darwin

package vmnethelper

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// ---------- BuildArgs ----------

func TestBuildArgs_Basic(t *testing.T) {
	cfg := HelperConfig{
		BinaryPath:    "/opt/homebrew/opt/vmnet-helper/libexec/vmnet-helper",
		OperationMode: ModeShared,
		SocketFD:      3,
	}
	got := BuildArgs(cfg)
	want := []string{
		"/opt/homebrew/opt/vmnet-helper/libexec/vmnet-helper",
		"--fd=3",
		"--operation-mode=shared",
	}
	assertArgsEqual(t, got, want)
}

func TestBuildArgs_WithIsolation(t *testing.T) {
	cfg := HelperConfig{
		BinaryPath:      "/opt/vmnet-helper/bin/vmnet-helper",
		OperationMode:   ModeShared,
		SocketFD:        3,
		EnableIsolation: true,
	}
	got := BuildArgs(cfg)
	if !contains(got, "--enable-isolation") {
		t.Errorf("expected --enable-isolation in %v", got)
	}
}

func TestBuildArgs_WithInterfaceID(t *testing.T) {
	cfg := HelperConfig{
		BinaryPath:    "/opt/vmnet-helper/bin/vmnet-helper",
		OperationMode: ModeShared,
		SocketFD:      3,
		InterfaceID:   "b7d6e6f4-0000-0000-0000-abcdefabcdef",
	}
	got := BuildArgs(cfg)
	if !contains(got, "--interface-id=b7d6e6f4-0000-0000-0000-abcdefabcdef") {
		t.Errorf("expected --interface-id=<uuid> in %v", got)
	}
}

func TestBuildArgs_WithSudo(t *testing.T) {
	cfg := HelperConfig{
		BinaryPath:    "/opt/vmnet-helper/bin/vmnet-helper",
		OperationMode: ModeShared,
		SocketFD:      3,
		UseSudo:       true,
	}
	got := BuildArgs(cfg)
	if len(got) < 3 || got[0] != "sudo" || got[1] != "-n" {
		t.Fatalf("expected ['sudo', '-n', ...]; got %v", got)
	}
	if got[2] != "/opt/vmnet-helper/bin/vmnet-helper" {
		t.Errorf("expected binary at argv[2]; got %q", got[2])
	}
}

func TestBuildArgs_Full(t *testing.T) {
	cfg := HelperConfig{
		BinaryPath:      "/opt/homebrew/opt/vmnet-helper/libexec/vmnet-helper",
		OperationMode:   ModeShared,
		SocketFD:        3,
		EnableIsolation: true,
		InterfaceID:     "ifid-123",
		UseSudo:         true,
	}
	got := BuildArgs(cfg)
	want := []string{
		"sudo", "-n",
		"/opt/homebrew/opt/vmnet-helper/libexec/vmnet-helper",
		"--fd=3",
		"--operation-mode=shared",
		"--enable-isolation",
		"--interface-id=ifid-123",
	}
	assertArgsEqual(t, got, want)
}

func TestBuildArgs_WithAddresses(t *testing.T) {
	cfg := HelperConfig{
		BinaryPath:    "/opt/vmnet-helper/bin/vmnet-helper",
		OperationMode: ModeHost,
		SocketFD:      3,
		StartAddress:  "192.168.128.1",
		EndAddress:    "192.168.128.254",
		SubnetMask:    "255.255.255.0",
	}
	got := BuildArgs(cfg)
	want := []string{
		"/opt/vmnet-helper/bin/vmnet-helper",
		"--fd=3",
		"--operation-mode=host",
		"--start-address=192.168.128.1",
		"--end-address=192.168.128.254",
		"--subnet-mask=255.255.255.0",
	}
	assertArgsEqual(t, got, want)
}

func TestBuildArgs_AddressesOmittedWhenEmpty(t *testing.T) {
	cfg := HelperConfig{
		BinaryPath:    "/opt/vmnet-helper/bin/vmnet-helper",
		OperationMode: ModeHost,
		SocketFD:      3,
	}
	got := BuildArgs(cfg)
	for _, flag := range []string{"--start-address=", "--end-address=", "--subnet-mask="} {
		for _, a := range got {
			if strings.HasPrefix(a, flag) {
				t.Errorf("unexpected %s in %v when addresses unset", flag, got)
			}
		}
	}
}

func TestBuildArgs_FixedOrder(t *testing.T) {
	// --fd must precede --operation-mode must precede conditional flags.
	cfg := HelperConfig{
		BinaryPath:      "/bin/vmnet-helper",
		OperationMode:   ModeHost,
		SocketFD:        3,
		EnableIsolation: true,
		InterfaceID:     "x",
	}
	got := BuildArgs(cfg)
	fdIdx := indexOf(got, "--fd=3")
	modeIdx := indexOf(got, "--operation-mode=host")
	isoIdx := indexOf(got, "--enable-isolation")
	idIdx := indexOf(got, "--interface-id=x")
	if fdIdx >= modeIdx || modeIdx >= isoIdx || isoIdx >= idIdx {
		t.Errorf("flags out of order: fd=%d mode=%d iso=%d id=%d in %v",
			fdIdx, modeIdx, isoIdx, idIdx, got)
	}
}

// ---------- parseStartJSON ----------

const sampleStartJSON = `{"vmnet_nat66_prefix":"fd00:abcd::","vmnet_mac_address":"aa:bb:cc:dd:ee:ff","vmnet_mtu":1500,"vmnet_max_packet_size":1514,"vmnet_start_address":"192.168.105.1","vmnet_end_address":"192.168.105.254","vmnet_subnet_mask":"255.255.255.0","vmnet_interface_id":"6F3E3B0C-1234-0000-0000-0000000000AA"}`

func TestParseStartJSON_Valid(t *testing.T) {
	sj, err := parseStartJSON([]byte(sampleStartJSON + "\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sj.StartAddress != "192.168.105.1" {
		t.Errorf("StartAddress = %q, want 192.168.105.1", sj.StartAddress)
	}
	if sj.EndAddress != "192.168.105.254" {
		t.Errorf("EndAddress = %q, want 192.168.105.254", sj.EndAddress)
	}
	if sj.SubnetMask != "255.255.255.0" {
		t.Errorf("SubnetMask = %q", sj.SubnetMask)
	}
	if sj.MTU != 1500 {
		t.Errorf("MTU = %d, want 1500", sj.MTU)
	}
	if sj.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC = %q", sj.MAC)
	}
	if sj.InterfaceID != "6F3E3B0C-1234-0000-0000-0000000000AA" {
		t.Errorf("InterfaceID = %q", sj.InterfaceID)
	}
	if sj.NAT66Prefix != "fd00:abcd::" {
		t.Errorf("NAT66Prefix = %q", sj.NAT66Prefix)
	}
}

func TestParseStartJSON_Malformed(t *testing.T) {
	_, err := parseStartJSON([]byte(`{"vmnet_start_address":"192.168.1.1"`))
	if err == nil {
		t.Fatal("expected error for truncated JSON")
	}
}

func TestParseStartJSON_EmptyLine(t *testing.T) {
	if _, err := parseStartJSON([]byte("")); err == nil {
		t.Error("expected error for empty line")
	}
	if _, err := parseStartJSON([]byte("   \n")); err == nil {
		t.Error("expected error for whitespace-only line")
	}
}

func TestParseStartJSON_MissingStartAddress(t *testing.T) {
	_, err := parseStartJSON([]byte(`{"vmnet_mtu":1500}`))
	if err == nil {
		t.Error("expected error when vmnet_start_address missing")
	}
}

// ---------- macOSMajor ----------

func TestMacOSMajor(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"15.4", 15},
		{"26.1.2", 26},
		{"10.15.7", 10},
		{"26", 26},
		{"", 0},
		{"bogus", 0},
		{"  14.2  ", 14},
	}
	for _, tt := range tests {
		if got := macOSMajor(tt.in); got != tt.want {
			t.Errorf("macOSMajor(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

// ---------- NeedsSudo ----------

func TestNeedsSudo_OldMacOS(t *testing.T) {
	resetSudoProbe()
	t.Cleanup(resetSudoProbe)
	productVersionFn = func() (string, error) { return "15.4", nil }
	t.Cleanup(func() { productVersionFn = readProductVersion })
	if !NeedsSudo() {
		t.Error("NeedsSudo() should return true on macOS 15")
	}
}

func TestNeedsSudo_NewMacOS(t *testing.T) {
	resetSudoProbe()
	t.Cleanup(resetSudoProbe)
	productVersionFn = func() (string, error) { return "26.0.1", nil }
	t.Cleanup(func() { productVersionFn = readProductVersion })
	if NeedsSudo() {
		t.Error("NeedsSudo() should return false on macOS 26")
	}
}

func TestNeedsSudo_ProbeError(t *testing.T) {
	resetSudoProbe()
	t.Cleanup(resetSudoProbe)
	productVersionFn = func() (string, error) { return "", errors.New("boom") }
	t.Cleanup(func() { productVersionFn = readProductVersion })
	if !NeedsSudo() {
		t.Error("NeedsSudo() should assume sudo needed on probe failure")
	}
}

func TestNeedsSudo_Unparseable(t *testing.T) {
	resetSudoProbe()
	t.Cleanup(resetSudoProbe)
	productVersionFn = func() (string, error) { return "totally bogus", nil }
	t.Cleanup(func() { productVersionFn = readProductVersion })
	if !NeedsSudo() {
		t.Error("NeedsSudo() should assume sudo needed when version unparseable")
	}
}

// ---------- ResolveBinaryPath ----------

func TestResolveBinaryPath_EnvOverride(t *testing.T) {
	f := filepath.Join(t.TempDir(), "vmnet-helper")
	if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envBinaryPath, f)

	got, err := ResolveBinaryPath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != f {
		t.Errorf("got %q, want %q", got, f)
	}
}

func TestResolveBinaryPath_EnvOverrideMissing(t *testing.T) {
	t.Setenv(envBinaryPath, filepath.Join(t.TempDir(), "does-not-exist"))
	_, err := ResolveBinaryPath()
	if err == nil {
		t.Fatal("expected error when env override points at nonexistent path")
	}
	if !strings.Contains(err.Error(), envBinaryPath) {
		t.Errorf("error should mention env var; got %v", err)
	}
}

func TestResolveBinaryPath_KnownPath(t *testing.T) {
	// Clear env override so the fallback chain is exercised.
	t.Setenv(envBinaryPath, "")

	fake := filepath.Join(t.TempDir(), "vmnet-helper-fake")
	if err := os.WriteFile(fake, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	prev := statFn
	t.Cleanup(func() { statFn = prev })
	statFn = func(name string) (os.FileInfo, error) {
		// Pretend only the first knownBinaryPaths entry exists.
		if name == knownBinaryPaths[0] {
			return os.Stat(fake)
		}
		return nil, os.ErrNotExist
	}

	got, err := ResolveBinaryPath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != knownBinaryPaths[0] {
		t.Errorf("got %q, want %q", got, knownBinaryPaths[0])
	}
}

func TestResolveBinaryPath_NotInstalled(t *testing.T) {
	t.Setenv(envBinaryPath, "")
	prev := statFn
	t.Cleanup(func() { statFn = prev })
	statFn = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }

	// Make PATH empty so LookPath fails.
	t.Setenv("PATH", "")

	_, err := ResolveBinaryPath()
	if err == nil {
		t.Fatal("expected error when binary cannot be resolved")
	}
	msg := err.Error()
	for _, hint := range []string{"brew", "install.sh", envBinaryPath} {
		if !strings.Contains(msg, hint) {
			t.Errorf("error missing hint %q; got: %s", hint, msg)
		}
	}
}

// ---------- Bridge discovery ----------

const sampleBridgeIfconfig = `lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether 14:98:77:ab:cd:ef
	inet 192.168.105.42 netmask 0xffffff00 broadcast 192.168.105.255
bridge101: flags=8a63<UP,BROADCAST,SMART,RUNNING,ALLMULTI,SIMPLEX,MULTICAST> mtu 1500
	options=3<RXCSUM,TXCSUM>
	ether 4a:00:6d:12:34:56
	inet 192.168.105.1 netmask 0xffffff00 broadcast 192.168.105.255
	member: vmenet1 flags=3<LEARNING,DISCOVER>
`

const sampleMultipleBridges = `bridge100: flags=8a63<UP>
	inet 192.168.64.1 netmask 0xffffff00
bridge101: flags=8a63<UP>
	inet 192.168.105.1 netmask 0xffffff00
bridge102: flags=8a63<UP>
	inet 192.168.120.1 netmask 0xffffff00
`

func TestParseBridgeFromIfconfig_Match(t *testing.T) {
	got, err := parseBridgeFromIfconfig(sampleBridgeIfconfig, "192.168.105.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "bridge101" {
		t.Errorf("got %q, want bridge101", got)
	}
}

func TestParseBridgeFromIfconfig_NoMatch(t *testing.T) {
	_, err := parseBridgeFromIfconfig(sampleBridgeIfconfig, "10.0.0.1")
	if err == nil {
		t.Error("expected error when no bridge matches")
	}
}

func TestParseBridgeFromIfconfig_MultipleBridges(t *testing.T) {
	got, err := parseBridgeFromIfconfig(sampleMultipleBridges, "192.168.120.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "bridge102" {
		t.Errorf("got %q, want bridge102", got)
	}
}

func TestParseBridgeFromIfconfig_NonBridgeHasMatchingIP(t *testing.T) {
	// en0 has 192.168.105.42; only bridge interfaces should be candidates,
	// so asking for 192.168.105.42 must NOT return en0 and must error.
	_, err := parseBridgeFromIfconfig(sampleBridgeIfconfig, "192.168.105.42")
	if err == nil {
		t.Error("non-bridge interface must not match")
	}
}

func TestParseBridgeFromIfconfig_InvalidGateway(t *testing.T) {
	if _, err := parseBridgeFromIfconfig(sampleBridgeIfconfig, "not-an-ip"); err == nil {
		t.Error("expected error for malformed gateway IP")
	}
}

func TestBridgeInterfaceForGateway_RetriesUntilFound(t *testing.T) {
	prev := runIfconfig
	prevSleep := sleepFn
	t.Cleanup(func() {
		runIfconfig = prev
		sleepFn = prevSleep
	})
	sleepFn = func(time.Duration) {}

	var calls int
	runIfconfig = func() (string, error) {
		calls++
		if calls < 3 {
			return "", nil // empty ifconfig, no match
		}
		return sampleBridgeIfconfig, nil
	}

	got, err := BridgeInterfaceForGateway("192.168.105.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "bridge101" {
		t.Errorf("got %q, want bridge101", got)
	}
	if calls != 3 {
		t.Errorf("expected 3 ifconfig calls, got %d", calls)
	}
}

func TestBridgeInterfaceForGateway_TimesOut(t *testing.T) {
	prev := runIfconfig
	prevSleep := sleepFn
	t.Cleanup(func() {
		runIfconfig = prev
		sleepFn = prevSleep
	})
	sleepFn = func(time.Duration) {}

	runIfconfig = func() (string, error) { return "", nil }

	_, err := BridgeInterfaceForGateway("192.168.105.1")
	if err == nil {
		t.Fatal("expected error when bridge never appears")
	}
}

func TestBridgeInterfaceForGateway_EmptyGateway(t *testing.T) {
	if _, err := BridgeInterfaceForGateway(""); err == nil {
		t.Error("expected error for empty gateway IP")
	}
}

// ---------- PID helpers (copied from vfkit test patterns) ----------

func TestReadPID_Valid(t *testing.T) {
	f := filepath.Join(t.TempDir(), "test.pid")
	if err := os.WriteFile(f, []byte("98765\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pid, err := ReadPID(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pid != 98765 {
		t.Errorf("got %d, want 98765", pid)
	}
}

func TestReadPID_Missing(t *testing.T) {
	if _, err := ReadPID(filepath.Join(t.TempDir(), "nope.pid")); err == nil {
		t.Error("expected error for missing PID file")
	}
}

func TestReadPID_Invalid(t *testing.T) {
	f := filepath.Join(t.TempDir(), "bad.pid")
	if err := os.WriteFile(f, []byte("banana\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPID(f); err == nil {
		t.Error("expected error for non-numeric PID")
	}
}

func TestReadPID_Zero(t *testing.T) {
	f := filepath.Join(t.TempDir(), "zero.pid")
	if err := os.WriteFile(f, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPID(f); err == nil {
		t.Error("expected error for PID 0")
	}
}

func TestReadPID_Negative(t *testing.T) {
	f := filepath.Join(t.TempDir(), "neg.pid")
	if err := os.WriteFile(f, []byte("-7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPID(f); err == nil {
		t.Error("expected error for negative PID")
	}
}

func TestIsRunning_MissingFile(t *testing.T) {
	if IsRunning(filepath.Join(t.TempDir(), "nope.pid")) {
		t.Error("IsRunning must be false for missing PID file")
	}
}

func TestCleanupPIDFile_Missing(t *testing.T) {
	// Missing PID file → no error (idempotent).
	if err := CleanupPIDFile(filepath.Join(t.TempDir(), "nope.pid")); err != nil {
		t.Errorf("unexpected error for missing file: %v", err)
	}
}

// ---------- splitInterfaceBlocks sanity check ----------

func TestSplitInterfaceBlocks(t *testing.T) {
	blocks := splitInterfaceBlocks(sampleBridgeIfconfig)
	if len(blocks) != 3 {
		t.Fatalf("expected 3 blocks, got %d", len(blocks))
	}
	if !strings.HasPrefix(blocks[0], "lo0:") {
		t.Errorf("block 0 not lo0: %q", truncate(blocks[0], 20))
	}
	if !strings.HasPrefix(blocks[2], "bridge101:") {
		t.Errorf("block 2 not bridge101: %q", truncate(blocks[2], 20))
	}
}

// ---------- helpers ----------

func assertArgsEqual(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("argv length: got %d, want %d\n  got:  %v\n  want: %v", len(got), len(want), got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func contains(args []string, s string) bool {
	return slices.Contains(args, s)
}

func indexOf(args []string, s string) int {
	for i, a := range args {
		if a == s {
			return i
		}
	}
	return -1
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
