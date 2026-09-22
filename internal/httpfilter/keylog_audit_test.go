package httpfilter

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
)

// TestKeyLogAudit verifies that starting/stopping TLS key logging emits a
// service-layer audit record — writing session secrets to disk is a distinct,
// security-sensitive fact that must be captured even for direct socket callers.
func TestKeyLogAudit(t *testing.T) {
	var buf bytes.Buffer
	restore := logging.SetAuditOutputForTest(&buf)
	defer restore()

	filter := allowlist.NewFilter()
	server := NewServer(filter, false)
	api := NewAPIServer(filepath.Join(t.TempDir(), "http.sock"), filter, server, nil, "box1")

	keyPath := filepath.Join(t.TempDir(), "keys.log")
	if _, err := api.StartKeyLog(context.Background(), &rpc.KeyLogReq{Path: keyPath}); err != nil {
		t.Fatalf("StartKeyLog: %v", err)
	}
	if _, err := api.StopKeyLog(context.Background(), &rpc.Empty{}); err != nil {
		t.Fatalf("StopKeyLog: %v", err)
	}

	// Count the unique action= attribute form: the action string also appears as
	// the record's msg, so counting the bare string would double it.
	out := buf.String()
	if got := strings.Count(out, "action="+logging.ActionKeyLogStart); got != 1 {
		t.Errorf("expected exactly 1 keylog start audit, got %d: %q", got, out)
	}
	if got := strings.Count(out, "action="+logging.ActionKeyLogStop); got != 1 {
		t.Errorf("expected exactly 1 keylog stop audit, got %d: %q", got, out)
	}
	// Attribution: instance, filter label, and the path written.
	for _, want := range []string{"instance=box1", "filter=http", "path=" + keyPath} {
		if !strings.Contains(out, want) {
			t.Errorf("keylog audit missing %q; got %q", want, out)
		}
	}
}
