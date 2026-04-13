//go:build linux

// Package libvirt implements the backend interface for libvirt/QEMU/KVM on Linux.
//
// This file contains the init() function that registers the backend.
// The registration happens automatically when this package is imported.
package libvirt

// The init() function in backend.go registers the libvirt backend.
// This file just documents that the registration happens on import.
