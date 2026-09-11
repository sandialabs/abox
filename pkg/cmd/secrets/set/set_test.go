package set

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadValue_ExactlyOneSource(t *testing.T) {
	// zero sources
	if _, err := readValue(&Options{}); err == nil {
		t.Error("expected error with no source")
	}
	// two sources
	if _, err := readValue(&Options{FromEnv: "X", Stdin: true}); err == nil {
		t.Error("expected error with two sources")
	}
}

func TestReadValue_FromFileTrimsNewline(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "key.txt")
	if err := os.WriteFile(p, []byte("sk-abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readValue(&Options{FromFile: p})
	if err != nil {
		t.Fatal(err)
	}
	if got != "sk-abc" {
		t.Errorf("got %q, want %q", got, "sk-abc")
	}
}

func TestReadValue_FromEnv(t *testing.T) {
	t.Setenv("ABOX_TEST_SECRET", "envval")
	got, err := readValue(&Options{FromEnv: "ABOX_TEST_SECRET"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "envval" {
		t.Errorf("got %q, want %q", got, "envval")
	}
	if _, err := readValue(&Options{FromEnv: "ABOX_TEST_UNSET_XYZ"}); err == nil {
		t.Error("expected error for unset env var")
	}
}

func TestTrimTrailingNewline(t *testing.T) {
	cases := map[string]string{
		"a\n":   "a",
		"a\r\n": "a",
		"a":     "a",
		"a\nb":  "a\nb", // only trailing newline trimmed
	}
	for in, want := range cases {
		if got := trimTrailingNewline(in); got != want {
			t.Errorf("trimTrailingNewline(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRunSet_UnknownInstance(t *testing.T) {
	err := runSet(&Options{Name: "definitely-not-an-instance-xyz", Key: "k", Stdin: true})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("expected does-not-exist error, got %v", err)
	}
}
