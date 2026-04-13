package cloudinit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/timeout"
	"github.com/sandialabs/abox/internal/validation"
)

// GenerateAndInstall creates a cloud-init ISO and installs it via the privilege helper.
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

	// Copy to final location via privileged helper
	ctx, cancel := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel()

	_, err = client.CopyFile(ctx, &rpc.CopyReq{
		Src: tempPath,
		Dst: paths.CloudInitISO,
	})
	if err != nil {
		return fmt.Errorf("failed to copy cloud-init ISO: %w", err)
	}

	// Set permissions for libvirt access
	ctx2, cancel2 := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel2()

	_, err = client.Chmod(ctx2, &rpc.ChmodReq{
		Path: paths.CloudInitISO,
		Mode: "644",
	})
	if err != nil {
		return fmt.Errorf("failed to set cloud-init ISO permissions: %w", err)
	}

	return nil
}
