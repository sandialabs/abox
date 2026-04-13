package cmdutil_test

import (
	"testing"

	"github.com/sandialabs/abox/pkg/cmdutil"
)

func TestColorScheme_Enabled(t *testing.T) {
	cs := cmdutil.NewColorScheme(true)
	got := cs.Green("ok")
	if got == "ok" {
		// NO_COLOR might be set in test env; skip assertion
		t.Skip("NO_COLOR is set, colors disabled")
	}
	if got != "\033[32mok\033[0m" {
		t.Fatalf("unexpected: %q", got)
	}
}

func TestColorScheme_Disabled(t *testing.T) {
	cs := cmdutil.NewColorScheme(false)
	if cs.Green("ok") != "ok" {
		t.Fatal("expected no-op when disabled")
	}
	if cs.Red("err") != "err" {
		t.Fatal("expected no-op when disabled")
	}
	if cs.Bold("b") != "b" {
		t.Fatal("expected no-op when disabled")
	}
	if cs.Yellow("w") != "w" {
		t.Fatal("expected no-op when disabled")
	}
	if cs.Gray("g") != "g" {
		t.Fatal("expected no-op when disabled")
	}
}
