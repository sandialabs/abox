//go:build darwin

package vfkit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildArgs_Basic(t *testing.T) {
	cfg := VMConfig{
		Name:       "test",
		CPUs:       2,
		MemoryMB:   4096,
		DiskPath:   "/tmp/disk.raw",
		MACAddress: "02:ab:00:11:22:33",
		NetFD:      NetFDChild,
	}

	args := BuildArgs(cfg)

	assertContains(t, args, "--cpus", "2")
	assertContains(t, args, "--memory", "4096")
	assertContainsDevice(t, args, "virtio-blk,path=/tmp/disk.raw")
	assertContainsDevice(t, args, "virtio-net,fd=3,mac=02:ab:00:11:22:33")
	assertContainsBootloader(t, args, "efi,variable-store=/tmp/efi-variable-store,create")

	// Should NOT contain cloud-init or console log devices
	for i, arg := range args {
		if arg == "--device" && i+1 < len(args) {
			if args[i+1] == "virtio-serial,logFilePath=" {
				t.Error("should not contain empty console log device")
			}
		}
	}
}

func TestBuildArgs_WithCloudInit(t *testing.T) {
	cfg := VMConfig{
		Name:         "test",
		CPUs:         1,
		MemoryMB:     2048,
		DiskPath:     "/tmp/disk.raw",
		CloudInitISO: "/tmp/cidata.iso",
		MACAddress:   "02:ab:00:44:55:66",
		NetFD:        NetFDChild,
	}

	args := BuildArgs(cfg)

	// Should have two virtio-blk devices: disk and cloud-init
	blkCount := 0
	for i, arg := range args {
		if arg == "--device" && i+1 < len(args) {
			if len(args[i+1]) > 10 && args[i+1][:10] == "virtio-blk" {
				blkCount++
			}
		}
	}
	if blkCount != 2 {
		t.Errorf("expected 2 virtio-blk devices, got %d", blkCount)
	}

	assertContainsDevice(t, args, "virtio-blk,path=/tmp/cidata.iso")
}

func TestBuildArgs_WithConsoleLog(t *testing.T) {
	cfg := VMConfig{
		Name:       "test",
		CPUs:       2,
		MemoryMB:   4096,
		DiskPath:   "/tmp/disk.raw",
		MACAddress: "02:ab:00:11:22:33",
		ConsoleLog: "/tmp/console.log",
		NetFD:      NetFDChild,
	}

	args := BuildArgs(cfg)
	assertContainsDevice(t, args, "virtio-serial,logFilePath=/tmp/console.log")
}

func TestBuildArgs_WithRESTAPI(t *testing.T) {
	cfg := VMConfig{
		Name:       "test",
		CPUs:       2,
		MemoryMB:   4096,
		DiskPath:   "/tmp/disk.raw",
		MACAddress: "02:ab:00:11:22:33",
		RESTfulURI: "tcp://localhost:12345",
		NetFD:      NetFDChild,
	}

	args := BuildArgs(cfg)
	assertContains(t, args, "--restful-uri", "tcp://localhost:12345")
}

func TestBuildArgs_Full(t *testing.T) {
	cfg := VMConfig{
		Name:         "myvm",
		CPUs:         4,
		MemoryMB:     8192,
		DiskPath:     "/data/instances/myvm/disk.raw",
		CloudInitISO: "/data/instances/myvm/cidata.iso",
		MACAddress:   "02:ab:00:aa:bb:cc",
		ConsoleLog:   "/data/instances/myvm/console.log",
		RESTfulURI:   "tcp://localhost:9999",
		NetFD:        NetFDChild,
	}

	args := BuildArgs(cfg)

	assertContains(t, args, "--cpus", "4")
	assertContains(t, args, "--memory", "8192")
	assertContainsDevice(t, args, "virtio-blk,path=/data/instances/myvm/disk.raw")
	assertContainsDevice(t, args, "virtio-blk,path=/data/instances/myvm/cidata.iso")
	assertContainsDevice(t, args, "virtio-net,fd=3,mac=02:ab:00:aa:bb:cc")
	assertContainsDevice(t, args, "virtio-serial,logFilePath=/data/instances/myvm/console.log")
	assertContainsBootloader(t, args, "efi,variable-store=/data/instances/myvm/efi-variable-store,create")
	assertContains(t, args, "--restful-uri", "tcp://localhost:9999")
}

func TestBuildArgs_NetFD(t *testing.T) {
	tests := []struct {
		name  string
		netFD int
		want  string
	}{
		{"fd 3", 3, "virtio-net,fd=3,mac=02:ab:00:11:22:33"},
		{"fd 7", 7, "virtio-net,fd=7,mac=02:ab:00:11:22:33"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := VMConfig{
				DiskPath:   "/tmp/disk.raw",
				MACAddress: "02:ab:00:11:22:33",
				NetFD:      tt.netFD,
			}
			args := BuildArgs(cfg)
			assertContainsDevice(t, args, tt.want)
		})
	}
}

func TestEFIStorePath(t *testing.T) {
	cfg := VMConfig{DiskPath: "/data/instances/myvm/disk.raw"}
	want := "/data/instances/myvm/efi-variable-store"
	if got := cfg.EFIStorePath(); got != want {
		t.Errorf("EFIStorePath() = %q, want %q", got, want)
	}
}

func TestReadPID_Valid(t *testing.T) {
	f := filepath.Join(t.TempDir(), "test.pid")
	if err := os.WriteFile(f, []byte("12345\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	pid, err := ReadPID(f)
	if err != nil {
		t.Fatalf("ReadPID() error: %v", err)
	}
	if pid != 12345 {
		t.Errorf("ReadPID() = %d, want 12345", pid)
	}
}

func TestReadPID_Missing(t *testing.T) {
	_, err := ReadPID(filepath.Join(t.TempDir(), "nonexistent.pid"))
	if err == nil {
		t.Error("ReadPID() should return error for missing file")
	}
}

func TestReadPID_Invalid(t *testing.T) {
	f := filepath.Join(t.TempDir(), "bad.pid")
	if err := os.WriteFile(f, []byte("notanumber\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := ReadPID(f)
	if err == nil {
		t.Error("ReadPID() should return error for non-numeric PID")
	}
}

func TestReadPID_Zero(t *testing.T) {
	f := filepath.Join(t.TempDir(), "zero.pid")
	if err := os.WriteFile(f, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := ReadPID(f)
	if err == nil {
		t.Error("ReadPID() should return error for PID 0")
	}
}

func TestReadPID_Negative(t *testing.T) {
	f := filepath.Join(t.TempDir(), "neg.pid")
	if err := os.WriteFile(f, []byte("-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := ReadPID(f)
	if err == nil {
		t.Error("ReadPID() should return error for negative PID")
	}
}

func TestAllocateRESTPort(t *testing.T) {
	port, err := AllocateRESTPort()
	if err != nil {
		t.Fatalf("AllocateRESTPort() error: %v", err)
	}
	if port <= 0 || port > 65535 {
		t.Errorf("AllocateRESTPort() = %d, want valid port", port)
	}
}

func TestRestBaseURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"tcp://localhost:12345", "http://localhost:12345"},
		{"tcp://127.0.0.1:9999", "http://127.0.0.1:9999"},
	}
	for _, tt := range tests {
		got := restBaseURL(tt.input)
		if got != tt.want {
			t.Errorf("restBaseURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// assertContains checks that args contains a flag followed by a value.
func assertContains(t *testing.T, args []string, flag, value string) {
	t.Helper()
	for i, arg := range args {
		if arg == flag && i+1 < len(args) && args[i+1] == value {
			return
		}
	}
	t.Errorf("args missing %s %s; got %v", flag, value, args)
}

// assertContainsDevice checks that args contains --device with the given value.
func assertContainsDevice(t *testing.T, args []string, device string) {
	t.Helper()
	assertContains(t, args, "--device", device)
}

// assertContainsBootloader checks that args contains --bootloader with the given value.
func assertContainsBootloader(t *testing.T, args []string, bootloader string) {
	t.Helper()
	assertContains(t, args, "--bootloader", bootloader)
}
