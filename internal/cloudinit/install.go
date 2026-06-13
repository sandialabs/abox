package cloudinit

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/timeout"
	"github.com/sandialabs/abox/internal/validation"
)

// GenerateAndInstall creates a cloud-init ISO and installs it to the instance's
// storage directory. On Linux, the copy goes through the privilege helper (storage
// is root-owned). On macOS, the copy is direct (storage is user-owned).
func GenerateAndInstall(client rpc.PrivilegeClient, inst *config.Instance, paths *config.Paths, contributors []Contributor) error {
	// Read the SSH public key
	pubKeyPath := paths.SSHKey + ".pub"
	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read SSH public key: %w", err)
	}
	pubKey := strings.TrimSpace(string(pubKeyBytes))

	// Validate SSH public key format
	if err := validation.ValidateSSHPublicKey(pubKey); err != nil {
		return fmt.Errorf("invalid SSH public key: %w", err)
	}

	// Create cloud-init config
	cfg := &Config{
		Hostname:     inst.Name,
		Username:     inst.GetUser(),
		SSHPublicKey: pubKey,
		MACAddress:   inst.MACAddress,
		Contributors: contributors,
	}

	// Create ISO in runtime directory
	tempDir := config.RuntimeDirOr(paths.Instance)
	tempPath := filepath.Join(tempDir, fmt.Sprintf("abox-cloudinit-%s.iso", inst.Name))
	defer os.Remove(tempPath)

	// Generate the ISO
	if err := CreateISO(tempPath, cfg); err != nil {
		return err
	}

	// Install to final location
	return installISO(client, tempPath, paths.CloudInitISO)
}

// installISO copies the generated ISO to its final location.
// On macOS, storage is user-owned so we copy directly.
// On Linux, storage is root-owned so we use the privilege helper.
func installISO(client rpc.PrivilegeClient, src, dst string) error {
	if runtime.GOOS == "darwin" {
		return installISODirect(src, dst)
	}
	return installISOPrivileged(client, src, dst)
}

// installISODirect copies the ISO directly (for user-owned storage on macOS).
func installISODirect(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { //nolint:gosec // user-owned storage directory
		return fmt.Errorf("failed to create ISO directory: %w", err)
	}

	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open cloud-init ISO: %w", err)
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create cloud-init ISO: %w", err)
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("failed to copy cloud-init ISO: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("failed to finalize cloud-init ISO: %w", err)
	}

	if err := os.Chmod(dst, 0o644); err != nil { //nolint:gosec // ISO must be readable by VM process
		return fmt.Errorf("failed to set cloud-init ISO permissions: %w", err)
	}

	return nil
}

// installISOPrivileged copies the ISO via the privilege helper (for root-owned storage on Linux).
func installISOPrivileged(client rpc.PrivilegeClient, src, dst string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel()

	_, err := client.CopyFile(ctx, &rpc.CopyReq{
		Src: src,
		Dst: dst,
	})
	if err != nil {
		return fmt.Errorf("failed to copy cloud-init ISO: %w", err)
	}

	// Set permissions for libvirt access
	ctx2, cancel2 := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel2()

	_, err = client.Chmod(ctx2, &rpc.ChmodReq{
		Path: dst,
		Mode: "644",
	})
	if err != nil {
		return fmt.Errorf("failed to set cloud-init ISO permissions: %w", err)
	}

	return nil
}
