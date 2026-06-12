//go:build darwin

package vfkit

import (
	"context"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
)

// Compile-time interface compliance check.
var _ backend.NetworkManager = (*NetworkManager)(nil)

func TestNetworkManager_Create(t *testing.T) {
	m := &NetworkManager{}
	inst := &config.Instance{Name: "test", Bridge: "abox-test"}
	if err := m.Create(context.Background(), inst); err != nil {
		t.Fatalf("Create() returned error: %v", err)
	}
}

func TestNetworkManager_Start(t *testing.T) {
	m := &NetworkManager{}
	if err := m.Start(context.Background(), "abox-test"); err != nil {
		t.Fatalf("Start() returned error: %v", err)
	}
}

func TestNetworkManager_Stop(t *testing.T) {
	m := &NetworkManager{}
	if err := m.Stop(context.Background(), "abox-test"); err != nil {
		t.Fatalf("Stop() returned error: %v", err)
	}
}

func TestNetworkManager_Delete(t *testing.T) {
	m := &NetworkManager{}
	if err := m.Delete(context.Background(), "abox-test"); err != nil {
		t.Fatalf("Delete() returned error: %v", err)
	}
}

func TestNetworkManager_Exists(t *testing.T) {
	m := &NetworkManager{}
	tests := []string{"abox-test", "abox-dev", "nonexistent", ""}
	for _, name := range tests {
		if !m.Exists(name) {
			t.Errorf("Exists(%q) = false, want true", name)
		}
	}
}

func TestNetworkManager_IsActive(t *testing.T) {
	m := &NetworkManager{}
	tests := []string{"abox-test", "abox-dev", "nonexistent", ""}
	for _, name := range tests {
		if !m.IsActive(name) {
			t.Errorf("IsActive(%q) = false, want true", name)
		}
	}
}
