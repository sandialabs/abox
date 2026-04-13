package iostreams

import (
	"bytes"
	"testing"
)

func TestTest_ReturnsFourValues(t *testing.T) {
	ios, stdin, stdout, stderr := Test()

	// Write to stdin and verify it's readable from ios.In
	stdin.WriteString("hello")
	buf := make([]byte, 5)
	n, err := ios.In.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("stdin = %q, want %q", string(buf[:n]), "hello")
	}

	// Write to ios.Out and verify it appears in stdout
	_, _ = ios.Out.Write([]byte("world"))
	if stdout.String() != "world" {
		t.Errorf("stdout = %q, want %q", stdout.String(), "world")
	}

	// Write to ios.ErrOut and verify it appears in stderr
	_, _ = ios.ErrOut.Write([]byte("err"))
	if stderr.String() != "err" {
		t.Errorf("stderr = %q, want %q", stderr.String(), "err")
	}
}

func TestIsTerminal_Buffer(t *testing.T) {
	ios, _, _, _ := Test()
	if ios.IsTerminal() {
		t.Error("expected IsTerminal() to be false for buffer-backed IOStreams")
	}
}

func TestIsTerminal_CachedAfterPager(t *testing.T) {
	// Verify that IsTerminal returns consistent results regardless of
	// Out being replaced (e.g. by StartPager).
	ios, _, _, _ := Test()
	before := ios.IsTerminal()
	ios.StartPager() // no-op for non-TTY, but exercises the path
	after := ios.IsTerminal()
	ios.StopPager()

	if before != after {
		t.Error("IsTerminal() changed after StartPager; expected cached value")
	}
}

func TestSetOutput_RestoreOutput(t *testing.T) {
	ios, _, stdout, _ := Test()
	override := new(bytes.Buffer)

	ios.SetOutput(override)
	_, _ = ios.Out.Write([]byte("redirected"))
	if override.String() != "redirected" {
		t.Error("SetOutput did not redirect Out")
	}
	if stdout.Len() != 0 {
		t.Error("original stdout should not have received output")
	}

	ios.RestoreOutput()
	_, _ = ios.Out.Write([]byte("restored"))
	if stdout.String() != "restored" {
		t.Error("RestoreOutput did not restore Out")
	}
}

func TestStartPager_NonTTY(t *testing.T) {
	ios, _, stdout, _ := Test()
	ios.StartPager() // should be a no-op for non-TTY

	_, _ = ios.Out.Write([]byte("no pager"))
	ios.StopPager()

	if stdout.String() != "no pager" {
		t.Errorf("expected output to go directly to stdout, got %q", stdout.String())
	}
}
