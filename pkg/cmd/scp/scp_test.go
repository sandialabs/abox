package scp

import (
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

func TestNewCmdSCP_FlagParsing(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdSCP(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"-r", "-p", "./local", "dev:/remote"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	if !gotOpts.Recursive {
		t.Error("expected Recursive to be true")
	}
	if !gotOpts.Preserve {
		t.Error("expected Preserve to be true")
	}
	if len(gotOpts.Srcs) != 1 || gotOpts.Srcs[0] != "./local" {
		t.Errorf("Srcs = %q, want %q", gotOpts.Srcs, []string{"./local"})
	}
	if gotOpts.Dst != "dev:/remote" {
		t.Errorf("Dst = %q, want %q", gotOpts.Dst, "dev:/remote")
	}
}

func TestNewCmdSCP_MultipleSources(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdSCP(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"a.txt", "b.txt", "c.txt", "dev:/home/ubuntu/"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	wantSrcs := []string{"a.txt", "b.txt", "c.txt"}
	if len(gotOpts.Srcs) != len(wantSrcs) {
		t.Fatalf("Srcs length = %d, want %d", len(gotOpts.Srcs), len(wantSrcs))
	}
	for i, want := range wantSrcs {
		if gotOpts.Srcs[i] != want {
			t.Errorf("Srcs[%d] = %q, want %q", i, gotOpts.Srcs[i], want)
		}
	}
	if gotOpts.Dst != "dev:/home/ubuntu/" {
		t.Errorf("Dst = %q, want %q", gotOpts.Dst, "dev:/home/ubuntu/")
	}
}

func TestNewCmdSCP_RequiresArgs(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	for _, args := range [][]string{{}, {"onlyone"}} {
		cmd := NewCmdSCP(f, func(o *Options) error {
			t.Fatal("runF should not be called")
			return nil
		})
		cmd.SetArgs(args)

		if err := cmd.Execute(); err == nil {
			t.Fatalf("expected error with args %v", args)
		}
	}
}

func TestRun_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		srcs    []string
		dst     string
		wantErr string
	}{
		{
			name:    "both sides local",
			srcs:    []string{"./a.txt"},
			dst:     "./b.txt",
			wantErr: "at least one path must be remote",
		},
		{
			name:    "both sides remote",
			srcs:    []string{"dev:/a.txt"},
			dst:     "dev:/b.txt",
			wantErr: "cannot copy between two remote instances",
		},
		{
			name:    "mixed local and remote sources",
			srcs:    []string{"./local.txt", "dev:/remote.txt"},
			dst:     "./dest",
			wantErr: "all source paths must be the same type",
		},
		{
			name:    "sources from different instances",
			srcs:    []string{"dev:/a.txt", "prod:/b.txt"},
			dst:     "./dest",
			wantErr: "all remote sources must be from the same instance",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Options{Srcs: tt.srcs, Dst: tt.dst}
			err := o.Run()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParseRemotePath(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantInst   string
		wantPath   string
		wantRemote bool
	}{
		{"remote path", "dev:/home/ubuntu/", "dev", "/home/ubuntu/", true},
		{"local path", "./local/file.txt", "", "./local/file.txt", false},
		{"no colon", "localfile", "", "localfile", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst, path, isRemote := parseRemotePath(tt.path)
			if inst != tt.wantInst {
				t.Errorf("instance = %q, want %q", inst, tt.wantInst)
			}
			if path != tt.wantPath {
				t.Errorf("path = %q, want %q", path, tt.wantPath)
			}
			if isRemote != tt.wantRemote {
				t.Errorf("isRemote = %v, want %v", isRemote, tt.wantRemote)
			}
		})
	}
}
