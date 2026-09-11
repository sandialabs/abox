package images

import (
	"runtime"
	"testing"
)

func TestHostArch(t *testing.T) {
	if got := hostArch(); got != runtime.GOARCH {
		t.Errorf("hostArch() = %q, want %q", got, runtime.GOARCH)
	}
}
