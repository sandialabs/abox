package allowlist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestModeController_SetGetActive(t *testing.T) {
	var mc ModeController

	// Default should be inactive (passive)
	if mc.IsActive() {
		t.Error("default should be inactive")
	}

	mc.SetActive(true)
	if !mc.IsActive() {
		t.Error("expected active after SetActive(true)")
	}

	mc.SetActive(false)
	if mc.IsActive() {
		t.Error("expected inactive after SetActive(false)")
	}
}

func TestModeController_GetMode(t *testing.T) {
	var mc ModeController

	if got := mc.GetMode(); got != "passive" {
		t.Errorf("GetMode() = %q, want %q", got, "passive")
	}

	mc.SetActive(true)
	if got := mc.GetMode(); got != "active" {
		t.Errorf("GetMode() = %q, want %q", got, "active")
	}
}

func TestModeController_SetListenPort(t *testing.T) {
	var mc ModeController

	mc.SetListenPort(8080)
	if got := mc.GetListenPort(); got != 8080 {
		t.Errorf("GetListenPort() = %d, want 8080", got)
	}

	mc.SetListenPort(0)
	if got := mc.GetListenPort(); got != 0 {
		t.Errorf("GetListenPort() = %d, want 0", got)
	}
}

func TestModeController_LogDomain_ActiveMode(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "profile.log")

	var mc ModeController
	if err := mc.InitProfileLogger(profilePath); err != nil {
		t.Fatalf("InitProfileLogger failed: %v", err)
	}

	mc.SetActive(true)
	mc.LogDomain("DNS", "example.com")

	// In active mode, nothing should be logged
	data, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if len(data) > 0 {
		t.Errorf("expected no data in active mode, got %q", string(data))
	}
}

func TestModeController_LogDomain_PassiveMode(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "profile.log")

	var mc ModeController
	if err := mc.InitProfileLogger(profilePath); err != nil {
		t.Fatalf("InitProfileLogger failed: %v", err)
	}

	mc.SetActive(false)
	mc.LogDomain("DNS", "example.com")

	data, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected domain to be logged in passive mode")
	}
}

func TestModeController_InitProfileLogger_Idempotent(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "profile.log")

	var mc ModeController
	if err := mc.InitProfileLogger(profilePath); err != nil {
		t.Fatalf("first init failed: %v", err)
	}
	if err := mc.InitProfileLogger(profilePath); err != nil {
		t.Fatalf("second init should succeed (idempotent): %v", err)
	}
}
