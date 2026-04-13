package allowlist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockModeServer implements ModeServer for testing.
type mockModeServer struct {
	active        bool
	profileLogger *ProfileLogger
}

func (m *mockModeServer) SetActive(active bool) {
	m.active = active
}

func (m *mockModeServer) IsActive() bool {
	return m.active
}

func (m *mockModeServer) GetProfileLogger() *ProfileLogger {
	return m.profileLogger
}

func (m *mockModeServer) GetMode() string {
	if m.active {
		return "active"
	}
	return "passive"
}

func TestAllowlistAPIHandler_Add(t *testing.T) {
	filter := NewFilter()
	handler := &AllowlistAPIHandler{
		Filter: filter,
	}

	t.Run("add-valid-domain", func(t *testing.T) {
		resp, err := handler.Add("github.com")
		if err != nil {
			t.Fatalf("Add failed: %v", err)
		}
		if !strings.Contains(resp.Message, "added") {
			t.Errorf("Expected 'added' in message, got %q", resp.Message)
		}

		if !filter.IsAllowed("github.com") {
			t.Error("Domain should be in allowlist")
		}
	})

	t.Run("add-duplicate-domain", func(t *testing.T) {
		resp, err := handler.Add("github.com")
		if err != nil {
			t.Fatalf("Add failed: %v", err)
		}
		if !strings.Contains(resp.Message, "already") {
			t.Errorf("Expected 'already' in message for duplicate, got %q", resp.Message)
		}
	})

	t.Run("add-invalid-domain", func(t *testing.T) {
		_, err := handler.Add("invalid..domain")
		if err == nil {
			t.Error("Expected error for invalid domain")
		}
		s, ok := status.FromError(err)
		if !ok || s.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument error, got %v", err)
		}
	})

	t.Run("add-domain-with-control-chars", func(t *testing.T) {
		_, err := handler.Add("domain\n.com")
		if err == nil {
			t.Error("Expected error for domain with control chars")
		}
	})
}

func TestAllowlistAPIHandler_Remove(t *testing.T) {
	filter := NewFilter()
	filter.Add("github.com")
	filter.Add("example.org")

	handler := &AllowlistAPIHandler{
		Filter: filter,
	}

	t.Run("remove-existing-domain", func(t *testing.T) {
		resp, err := handler.Remove("github.com")
		if err != nil {
			t.Fatalf("Remove failed: %v", err)
		}
		if !strings.Contains(resp.Message, "removed") {
			t.Errorf("Expected 'removed' in message, got %q", resp.Message)
		}

		if filter.IsAllowed("github.com") {
			t.Error("Domain should not be in allowlist after removal")
		}
	})

	t.Run("remove-nonexistent-domain", func(t *testing.T) {
		_, err := handler.Remove("notfound.com")
		if err == nil {
			t.Error("Expected error for nonexistent domain")
		}
		s, ok := status.FromError(err)
		if !ok || s.Code() != codes.NotFound {
			t.Errorf("Expected NotFound error, got %v", err)
		}
	})

	t.Run("remove-invalid-domain", func(t *testing.T) {
		_, err := handler.Remove("invalid..domain")
		if err == nil {
			t.Error("Expected error for invalid domain")
		}
		s, ok := status.FromError(err)
		if !ok || s.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument error, got %v", err)
		}
	})
}

func TestAllowlistAPIHandler_List(t *testing.T) {
	filter := NewFilter()
	handler := &AllowlistAPIHandler{
		Filter: filter,
	}

	t.Run("empty-list", func(t *testing.T) {
		resp, err := handler.List()
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		if len(resp.Domains) != 0 {
			t.Errorf("Expected empty list, got %v", resp.Domains)
		}
	})

	t.Run("with-domains", func(t *testing.T) {
		filter.Add("github.com")
		filter.Add("example.org")

		resp, err := handler.List()
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		if len(resp.Domains) != 2 {
			t.Errorf("Expected 2 domains, got %d", len(resp.Domains))
		}
	})
}

func TestAllowlistAPIHandler_Reload(t *testing.T) {
	filter := NewFilter()
	handler := &AllowlistAPIHandler{
		Filter: filter,
	}

	t.Run("reload-without-loader", func(t *testing.T) {
		_, err := handler.Reload()
		if err == nil {
			t.Error("Expected error when no loader configured")
		}
		s, ok := status.FromError(err)
		if !ok || s.Code() != codes.FailedPrecondition {
			t.Errorf("Expected FailedPrecondition error, got %v", err)
		}
	})

	t.Run("reload-with-loader", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "allowlist.conf")

		// Create a config file
		err := os.WriteFile(configFile, []byte("github.com\nexample.org\n"), 0o600)
		if err != nil {
			t.Fatalf("Failed to create config file: %v", err)
		}

		loader := NewLoader(configFile, filter)
		handler.Loader = loader

		resp, err := handler.Reload()
		if err != nil {
			t.Fatalf("Reload failed: %v", err)
		}
		if !strings.Contains(resp.Message, "reloaded") {
			t.Errorf("Expected 'reloaded' in message, got %q", resp.Message)
		}
		if filter.Count() != 2 {
			t.Errorf("Expected 2 domains after reload, got %d", filter.Count())
		}
	})
}

func TestAllowlistAPIHandler_SetMode(t *testing.T) {
	filter := NewFilter()
	server := &mockModeServer{active: true}
	handler := &AllowlistAPIHandler{
		Filter: filter,
		Server: server,
	}

	t.Run("get-current-mode", func(t *testing.T) {
		resp, err := handler.SetMode("")
		if err != nil {
			t.Fatalf("SetMode failed: %v", err)
		}
		if !strings.Contains(resp.Message, "active") {
			t.Errorf("Expected 'active' in message, got %q", resp.Message)
		}
	})

	t.Run("set-passive", func(t *testing.T) {
		resp, err := handler.SetMode("passive")
		if err != nil {
			t.Fatalf("SetMode failed: %v", err)
		}
		if !strings.Contains(resp.Message, "passive") {
			t.Errorf("Expected 'passive' in message, got %q", resp.Message)
		}
		if server.IsActive() {
			t.Error("Server should be in passive mode")
		}
	})

	t.Run("set-active", func(t *testing.T) {
		resp, err := handler.SetMode("active")
		if err != nil {
			t.Fatalf("SetMode failed: %v", err)
		}
		if !strings.Contains(resp.Message, "active") {
			t.Errorf("Expected 'active' in message, got %q", resp.Message)
		}
		if !server.IsActive() {
			t.Error("Server should be in active mode")
		}
	})

	t.Run("set-invalid-mode", func(t *testing.T) {
		_, err := handler.SetMode("invalid")
		if err == nil {
			t.Error("Expected error for invalid mode")
		}
		s, ok := status.FromError(err)
		if !ok || s.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument error, got %v", err)
		}
	})
}

func TestAllowlistAPIHandler_Profile(t *testing.T) {
	filter := NewFilter()
	server := &mockModeServer{active: true}
	handler := &AllowlistAPIHandler{
		Filter: filter,
		Server: server,
	}

	t.Run("show-without-logger", func(t *testing.T) {
		resp, err := handler.Profile("show")
		if err != nil {
			t.Fatalf("Profile failed: %v", err)
		}
		if !strings.Contains(resp.Message, "no domains") {
			t.Errorf("Expected 'no domains' message, got %q", resp.Message)
		}
	})

	t.Run("count-without-logger", func(t *testing.T) {
		resp, err := handler.Profile("count")
		if err != nil {
			t.Fatalf("Profile failed: %v", err)
		}
		if resp.Count != 0 {
			t.Errorf("Expected count 0, got %d", resp.Count)
		}
	})

	t.Run("export-without-logger", func(t *testing.T) {
		resp, err := handler.Profile("export")
		if err != nil {
			t.Fatalf("Profile failed: %v", err)
		}
		if !strings.Contains(resp.Message, "No domains") {
			t.Errorf("Expected 'No domains' message, got %q", resp.Message)
		}
	})

	t.Run("clear-without-logger", func(t *testing.T) {
		resp, err := handler.Profile("clear")
		if err != nil {
			t.Fatalf("Profile failed: %v", err)
		}
		if !strings.Contains(resp.Message, "no domains") {
			t.Errorf("Expected 'no domains' message, got %q", resp.Message)
		}
	})

	t.Run("with-logger", func(t *testing.T) {
		tmpDir := t.TempDir()
		profileLog := filepath.Join(tmpDir, "profile.log")

		logger, err := NewProfileLogger(profileLog)
		if err != nil {
			t.Fatalf("NewProfileLogger failed: %v", err)
		}
		server.profileLogger = logger

		// Log a domain
		logger.LogDomain("test", "github.com")
		logger.LogDomain("test", "example.org")

		// Test show
		resp, err := handler.Profile("show")
		if err != nil {
			t.Fatalf("Profile show failed: %v", err)
		}
		if len(resp.Domains) != 2 {
			t.Errorf("Expected 2 domains, got %d", len(resp.Domains))
		}

		// Test count
		resp, err = handler.Profile("count")
		if err != nil {
			t.Fatalf("Profile count failed: %v", err)
		}
		if resp.Count != 2 {
			t.Errorf("Expected count 2, got %d", resp.Count)
		}

		// Test export
		resp, err = handler.Profile("export")
		if err != nil {
			t.Fatalf("Profile export failed: %v", err)
		}
		if !strings.Contains(resp.Message, "github.com") {
			t.Error("Export should contain github.com")
		}

		// Test clear
		resp, err = handler.Profile("clear")
		if err != nil {
			t.Fatalf("Profile clear failed: %v", err)
		}
		if !strings.Contains(resp.Message, "cleared") {
			t.Errorf("Expected 'cleared' in message, got %q", resp.Message)
		}

		// Verify cleared
		resp, err = handler.Profile("count")
		if err != nil {
			t.Fatalf("Profile count failed: %v", err)
		}
		if resp.Count != 0 {
			t.Errorf("Expected count 0 after clear, got %d", resp.Count)
		}
	})

	t.Run("invalid-subcommand", func(t *testing.T) {
		_, err := handler.Profile("invalid")
		if err == nil {
			t.Error("Expected error for invalid subcommand")
		}
		s, ok := status.FromError(err)
		if !ok || s.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument error, got %v", err)
		}
	})
}
