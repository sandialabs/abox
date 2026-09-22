//go:build windows

package main

// Register the VM backend on Windows via blank import (experimental vmware only;
// libvirt is Linux-only). Mirrors pkg/cmd/root/backends_windows.go.
import _ "github.com/sandialabs/abox/internal/backend/vmware"
