package vmrun

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// captureRun records the args of the last vmrun invocation and returns canned
// output/err.
func captureRun(out []byte, err error) (*[]string, func(ctx context.Context, name string, args ...string) ([]byte, error)) {
	var got []string
	fn := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		got = append([]string{name}, args...)
		return out, err
	}
	return &got, fn
}

func TestVMRunArgVectors(t *testing.T) {
	// Pin the host driver so the expected argv is stable regardless of the OS the
	// test runs on (vmrunHostType() would return "fusion" on macOS).
	t.Setenv(envVmrunHostType, "ws")
	cases := []struct {
		name string
		call func(ctx context.Context) error
		want []string
	}{
		{
			name: "Start",
			call: func(ctx context.Context) error { return Start(ctx, "/d/disk.vmx") },
			want: []string{"vmrun", "-T", "ws", "start", "/d/disk.vmx", "nogui"},
		},
		{
			name: "Stop",
			call: func(ctx context.Context) error { return Stop(ctx, "/d/disk.vmx") },
			want: []string{"vmrun", "-T", "ws", "stop", "/d/disk.vmx", "soft"},
		},
		{
			name: "ForceStop",
			call: func(ctx context.Context) error { return ForceStop(ctx, "/d/disk.vmx") },
			want: []string{"vmrun", "-T", "ws", "stop", "/d/disk.vmx", "hard"},
		},
		{
			name: "DeleteVM",
			call: func(ctx context.Context) error { return DeleteVM(ctx, "/d/disk.vmx") },
			want: []string{"vmrun", "-T", "ws", "deleteVM", "/d/disk.vmx"},
		},
		{
			name: "CreateSnapshot",
			call: func(ctx context.Context) error { return CreateSnapshot(ctx, "/d/disk.vmx", "snap1") },
			want: []string{"vmrun", "-T", "ws", "snapshot", "/d/disk.vmx", "snap1"},
		},
		{
			name: "RevertToSnapshot",
			call: func(ctx context.Context) error { return RevertToSnapshot(ctx, "/d/disk.vmx", "snap1") },
			want: []string{"vmrun", "-T", "ws", "revertToSnapshot", "/d/disk.vmx", "snap1"},
		},
		{
			name: "DeleteSnapshot",
			call: func(ctx context.Context) error { return DeleteSnapshot(ctx, "/d/disk.vmx", "snap1") },
			want: []string{"vmrun", "-T", "ws", "deleteSnapshot", "/d/disk.vmx", "snap1"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, fn := captureRun(nil, nil)
			restore := SetRunCommandForTest(fn)
			defer restore()
			if err := c.call(context.Background()); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if !reflect.DeepEqual(*got, c.want) {
				t.Errorf("%s args = %v, want %v", c.name, *got, c.want)
			}
		})
	}
}

// TestVMRunHostTypeEnvOverride asserts ABOX_VMRUN_HOSTTYPE overrides the GOOS
// default and reaches vmrun's "-T" prefix.
func TestVMRunHostTypeEnvOverride(t *testing.T) {
	t.Setenv(envVmrunHostType, "player")
	got, fn := captureRun(nil, nil)
	restore := SetRunCommandForTest(fn)
	defer restore()
	if err := Start(context.Background(), "/d/disk.vmx"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	want := []string{"vmrun", "-T", "player", "start", "/d/disk.vmx", "nogui"}
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("args = %v want %v", *got, want)
	}
}

// TestSnapshotNameValidation asserts each snapshot method rejects an invalid name
// (e.g. one starting with '-', which vmrun would treat as a flag) BEFORE vmrun is
// invoked, and passes a valid name through. The revert/remove paths do not
// otherwise validate, so this is their only guard.
func TestSnapshotNameValidation(t *testing.T) {
	methods := []struct {
		name string
		call func(ctx context.Context, name string) error
	}{
		{"CreateSnapshot", func(ctx context.Context, n string) error { return CreateSnapshot(ctx, "/d/disk.vmx", n) }},
		{"RevertToSnapshot", func(ctx context.Context, n string) error { return RevertToSnapshot(ctx, "/d/disk.vmx", n) }},
		{"DeleteSnapshot", func(ctx context.Context, n string) error { return DeleteSnapshot(ctx, "/d/disk.vmx", n) }},
	}
	badNames := []string{"-h", "--", "-rf", "bad;name", "with space", ""}

	for _, m := range methods {
		for _, bad := range badNames {
			t.Run(m.name+"/rejects/"+bad, func(t *testing.T) {
				got, fn := captureRun(nil, nil)
				restore := SetRunCommandForTest(fn)
				defer restore()
				if err := m.call(context.Background(), bad); err == nil {
					t.Fatalf("%s(%q): expected validation error", m.name, bad)
				}
				if len(*got) != 0 {
					t.Errorf("%s(%q): vmrun invoked despite invalid name: %v", m.name, bad, *got)
				}
			})
		}
		t.Run(m.name+"/accepts/valid", func(t *testing.T) {
			got, fn := captureRun(nil, nil)
			restore := SetRunCommandForTest(fn)
			defer restore()
			if err := m.call(context.Background(), "snap1"); err != nil {
				t.Fatalf("%s(valid): %v", m.name, err)
			}
			if len(*got) == 0 {
				t.Errorf("%s(valid): expected vmrun to be invoked", m.name)
			}
		})
	}
}

func TestListRunning_Parsing(t *testing.T) {
	out := "Total running VMs: 2\n/home/u/a/disk.vmx\n/home/u/b/disk.vmx\n"
	_, fn := captureRun([]byte(out), nil)
	restore := SetRunCommandForTest(fn)
	defer restore()

	got, err := ListRunning(context.Background())
	if err != nil {
		t.Fatalf("ListRunning: %v", err)
	}
	want := []string{"/home/u/a/disk.vmx", "/home/u/b/disk.vmx"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListRunning = %v want %v", got, want)
	}
}

func TestListRunning_Empty(t *testing.T) {
	_, fn := captureRun([]byte("Total running VMs: 0\n"), nil)
	restore := SetRunCommandForTest(fn)
	defer restore()

	got, err := ListRunning(context.Background())
	if err != nil {
		t.Fatalf("ListRunning: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("ListRunning = %v want empty", got)
	}
}

func TestListSnapshots_Parsing(t *testing.T) {
	out := "Total snapshots: 2\nsnap1\nsnap2\n"
	_, fn := captureRun([]byte(out), nil)
	restore := SetRunCommandForTest(fn)
	defer restore()

	got, err := ListSnapshots(context.Background(), "/d/disk.vmx")
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	want := []string{"snap1", "snap2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListSnapshots = %v want %v", got, want)
	}
}

func TestVMRun_ErrorWrapsOutput(t *testing.T) {
	_, fn := captureRun([]byte("Error: the VM is not powered on"), errors.New("exit status 255"))
	restore := SetRunCommandForTest(fn)
	defer restore()

	err := Start(context.Background(), "/d/disk.vmx")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "the VM is not powered on") {
		t.Errorf("error should include command output, got: %v", err)
	}
	if !strings.Contains(err.Error(), "exit status 255") {
		t.Errorf("error should wrap underlying error, got: %v", err)
	}
}
