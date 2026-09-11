// Package mock provides mock implementations of backend interfaces for testing.
package mock

import (
	"context"
	"fmt"
	"io"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
)

// Backend implements backend.Backend with configurable function hooks.
// Any hook that is nil returns a sensible default.
// To also implement backend.TemplateValidator, embed a TemplateValidator:
//
//	&struct{ *mock.Backend; mock.TemplateValidator }{ ... }
type Backend struct {
	NameFunc             func() string
	IsAvailableFunc      func() error
	VMFunc               func() backend.VMManager
	NetworkFunc          func() backend.NetworkManager
	DiskFunc             func() backend.DiskManager
	SnapshotFunc         func() backend.SnapshotManager
	EgressControllerFunc func() backend.EgressController
	MonitorTransportFunc func() backend.MonitorTransport
	DryRunFunc           func(inst *config.Instance, paths *config.Paths, w io.Writer, opts backend.VMCreateOptions) error
	ResourceNamesFunc    func(string) backend.ResourceNames
	GenerateMACFunc      func() string
	StorageDirFunc       func() string
}

func (b *Backend) Name() string {
	if b.NameFunc != nil {
		return b.NameFunc()
	}
	return "mock"
}

func (b *Backend) IsAvailable() error {
	if b.IsAvailableFunc != nil {
		return b.IsAvailableFunc()
	}
	return nil
}

func (b *Backend) VM() backend.VMManager {
	if b.VMFunc != nil {
		return b.VMFunc()
	}
	return &VMManager{}
}

func (b *Backend) Network() backend.NetworkManager {
	if b.NetworkFunc != nil {
		return b.NetworkFunc()
	}
	return &NetworkManager{}
}

func (b *Backend) Disk() backend.DiskManager {
	if b.DiskFunc != nil {
		return b.DiskFunc()
	}
	return &DiskManager{}
}

func (b *Backend) Snapshot() backend.SnapshotManager {
	if b.SnapshotFunc != nil {
		return b.SnapshotFunc()
	}
	return &SnapshotManager{}
}

func (b *Backend) EgressController() backend.EgressController {
	if b.EgressControllerFunc != nil {
		return b.EgressControllerFunc()
	}
	return &EgressController{}
}

func (b *Backend) MonitorTransport() backend.MonitorTransport {
	if b.MonitorTransportFunc != nil {
		return b.MonitorTransportFunc()
	}
	return MonitorTransport{Device: "/dev/virtio-ports/abox.monitor.0"}
}

// MonitorTransport is a mock backend.MonitorTransport.
type MonitorTransport struct {
	Device string
}

// GuestDevice returns the configured guest device path.
func (t MonitorTransport) GuestDevice() string { return t.Device }

func (b *Backend) DryRun(inst *config.Instance, paths *config.Paths, w io.Writer, opts backend.VMCreateOptions) error {
	if b.DryRunFunc != nil {
		return b.DryRunFunc(inst, paths, w, opts)
	}
	fmt.Fprintf(w, "=== Mock Dry Run for %s ===\n", inst.Name)
	return nil
}

func (b *Backend) ResourceNames(instanceName string) backend.ResourceNames {
	if b.ResourceNamesFunc != nil {
		return b.ResourceNamesFunc(instanceName)
	}
	return backend.ResourceNames{
		Instance: instanceName,
		VM:       "mock-" + instanceName,
		Network:  "mock-" + instanceName,
	}
}

func (b *Backend) GenerateMAC() string {
	if b.GenerateMACFunc != nil {
		return b.GenerateMACFunc()
	}
	return "52:54:00:00:00:01"
}

func (b *Backend) StorageDir() string {
	if b.StorageDirFunc != nil {
		return b.StorageDirFunc()
	}
	return "/tmp/abox-mock"
}

// TemplateValidator implements backend.TemplateValidator with configurable function hooks.
// Embed alongside Backend to create a backend that supports custom templates:
//
//	be := &struct{ *mock.Backend; mock.TemplateValidator }{ Backend: &mock.Backend{}, TemplateValidator: mock.TemplateValidator{} }
type TemplateValidator struct {
	ValidateCustomTemplateFunc func(string) error
	HasCustomTemplateFunc      func(*config.Instance) bool
	SetCustomTemplateFunc      func(*config.Instance, bool)
	LoadCustomTemplateFunc     func(*config.Paths) (string, error)
	StoreCustomTemplateFunc    func(*config.Paths, string) error
}

func (v *TemplateValidator) ValidateCustomTemplate(content string) error {
	if v.ValidateCustomTemplateFunc != nil {
		return v.ValidateCustomTemplateFunc(content)
	}
	return nil
}

func (v *TemplateValidator) HasCustomTemplate(inst *config.Instance) bool {
	if v.HasCustomTemplateFunc != nil {
		return v.HasCustomTemplateFunc(inst)
	}
	return false
}

func (v *TemplateValidator) SetCustomTemplate(inst *config.Instance, has bool) {
	if v.SetCustomTemplateFunc != nil {
		v.SetCustomTemplateFunc(inst, has)
	}
}

func (v *TemplateValidator) LoadCustomTemplate(paths *config.Paths) (string, error) {
	if v.LoadCustomTemplateFunc != nil {
		return v.LoadCustomTemplateFunc(paths)
	}
	return "", nil
}

func (v *TemplateValidator) StoreCustomTemplate(paths *config.Paths, content string) error {
	if v.StoreCustomTemplateFunc != nil {
		return v.StoreCustomTemplateFunc(paths, content)
	}
	return nil
}

// VMManager implements backend.VMManager with configurable function hooks.
type VMManager struct {
	CreateFunc    func(ctx context.Context, inst *config.Instance, paths *config.Paths, opts backend.VMCreateOptions) error
	StartFunc     func(ctx context.Context, name string) error
	StopFunc      func(ctx context.Context, name string) error
	ForceStopFunc func(ctx context.Context, name string) error
	RemoveFunc    func(ctx context.Context, name string) error
	ExistsFunc    func(name string) bool
	IsRunningFunc func(name string) bool
	StateFunc     func(name string) backend.VMState
	GetIPFunc     func(name string) (string, error)
	GetUUIDFunc   func(name string) string
	RedefineFunc  func(ctx context.Context, inst *config.Instance, paths *config.Paths, opts backend.VMCreateOptions) error
}

func (m *VMManager) Create(ctx context.Context, inst *config.Instance, paths *config.Paths, opts backend.VMCreateOptions) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, inst, paths, opts)
	}
	return nil
}

func (m *VMManager) Start(ctx context.Context, name string) error {
	if m.StartFunc != nil {
		return m.StartFunc(ctx, name)
	}
	return nil
}

func (m *VMManager) Stop(ctx context.Context, name string) error {
	if m.StopFunc != nil {
		return m.StopFunc(ctx, name)
	}
	return nil
}

func (m *VMManager) ForceStop(ctx context.Context, name string) error {
	if m.ForceStopFunc != nil {
		return m.ForceStopFunc(ctx, name)
	}
	return nil
}

func (m *VMManager) Remove(ctx context.Context, name string) error {
	if m.RemoveFunc != nil {
		return m.RemoveFunc(ctx, name)
	}
	return nil
}

func (m *VMManager) Exists(name string) bool {
	if m.ExistsFunc != nil {
		return m.ExistsFunc(name)
	}
	return true
}

func (m *VMManager) IsRunning(name string) bool {
	if m.IsRunningFunc != nil {
		return m.IsRunningFunc(name)
	}
	return true
}

func (m *VMManager) State(name string) backend.VMState {
	if m.StateFunc != nil {
		return m.StateFunc(name)
	}
	return backend.VMStateRunning
}

func (m *VMManager) GetIP(name string) (string, error) {
	if m.GetIPFunc != nil {
		return m.GetIPFunc(name)
	}
	return "10.10.10.2", nil
}

func (m *VMManager) GetUUID(name string) string {
	if m.GetUUIDFunc != nil {
		return m.GetUUIDFunc(name)
	}
	return "00000000-0000-0000-0000-000000000000"
}

func (m *VMManager) Redefine(ctx context.Context, inst *config.Instance, paths *config.Paths, opts backend.VMCreateOptions) error {
	if m.RedefineFunc != nil {
		return m.RedefineFunc(ctx, inst, paths, opts)
	}
	return nil
}

// NetworkManager implements backend.NetworkManager with configurable function hooks.
type NetworkManager struct {
	CreateFunc   func(ctx context.Context, inst *config.Instance) error
	StartFunc    func(ctx context.Context, name string) error
	StopFunc     func(ctx context.Context, name string) error
	DeleteFunc   func(ctx context.Context, name string) error
	ExistsFunc   func(name string) bool
	IsActiveFunc func(name string) bool
}

func (m *NetworkManager) Create(ctx context.Context, inst *config.Instance) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, inst)
	}
	return nil
}

func (m *NetworkManager) Start(ctx context.Context, name string) error {
	if m.StartFunc != nil {
		return m.StartFunc(ctx, name)
	}
	return nil
}

func (m *NetworkManager) Stop(ctx context.Context, name string) error {
	if m.StopFunc != nil {
		return m.StopFunc(ctx, name)
	}
	return nil
}

func (m *NetworkManager) Delete(ctx context.Context, name string) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, name)
	}
	return nil
}

func (m *NetworkManager) Exists(name string) bool {
	if m.ExistsFunc != nil {
		return m.ExistsFunc(name)
	}
	return true
}

func (m *NetworkManager) IsActive(name string) bool {
	if m.IsActiveFunc != nil {
		return m.IsActiveFunc(name)
	}
	return true
}

// DiskManager implements backend.DiskManager with configurable function hooks.
type DiskManager struct {
	CreateFunc          func(ctx context.Context, inst *config.Instance, paths *config.Paths) error
	DeleteFunc          func(ctx context.Context, paths *config.Paths) error
	EnsureBaseImageFunc func(ctx context.Context, inst *config.Instance, paths *config.Paths) error
	EnsureAccessFunc    func(ctx context.Context, inst *config.Instance, paths *config.Paths) error
	ImportFunc          func(ctx context.Context, src string, inst *config.Instance, paths *config.Paths, snapshot bool) error
	ExportFunc          func(ctx context.Context, dst string, paths *config.Paths, snapshot bool) error
}

func (m *DiskManager) Create(ctx context.Context, inst *config.Instance, paths *config.Paths) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, inst, paths)
	}
	return nil
}

func (m *DiskManager) Delete(ctx context.Context, paths *config.Paths) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, paths)
	}
	return nil
}

func (m *DiskManager) EnsureBaseImage(ctx context.Context, inst *config.Instance, paths *config.Paths) error {
	if m.EnsureBaseImageFunc != nil {
		return m.EnsureBaseImageFunc(ctx, inst, paths)
	}
	return nil
}

func (m *DiskManager) EnsureAccess(ctx context.Context, inst *config.Instance, paths *config.Paths) error {
	if m.EnsureAccessFunc != nil {
		return m.EnsureAccessFunc(ctx, inst, paths)
	}
	return nil
}

func (m *DiskManager) Import(ctx context.Context, src string, inst *config.Instance, paths *config.Paths, snapshot bool) error {
	if m.ImportFunc != nil {
		return m.ImportFunc(ctx, src, inst, paths, snapshot)
	}
	return nil
}

func (m *DiskManager) Export(ctx context.Context, dst string, paths *config.Paths, snapshot bool) error {
	if m.ExportFunc != nil {
		return m.ExportFunc(ctx, dst, paths, snapshot)
	}
	return nil
}

// SnapshotManager implements backend.SnapshotManager with configurable function hooks.
type SnapshotManager struct {
	CreateFunc  func(ctx context.Context, vmName, snapshotName, description string) error
	ListFunc    func(ctx context.Context, vmName string) ([]backend.SnapshotInfo, error)
	RevertFunc  func(ctx context.Context, vmName, snapshotName string) error
	DeleteFunc  func(ctx context.Context, vmName, snapshotName string) error
	ExistsFunc  func(vmName, snapshotName string) bool
	GetInfoFunc func(vmName, snapshotName string) (backend.SnapshotInfo, error)
}

func (m *SnapshotManager) Create(ctx context.Context, vmName, snapshotName, description string) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, vmName, snapshotName, description)
	}
	return nil
}

func (m *SnapshotManager) List(ctx context.Context, vmName string) ([]backend.SnapshotInfo, error) {
	if m.ListFunc != nil {
		return m.ListFunc(ctx, vmName)
	}
	return nil, nil
}

func (m *SnapshotManager) Revert(ctx context.Context, vmName, snapshotName string) error {
	if m.RevertFunc != nil {
		return m.RevertFunc(ctx, vmName, snapshotName)
	}
	return nil
}

func (m *SnapshotManager) Delete(ctx context.Context, vmName, snapshotName string) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, vmName, snapshotName)
	}
	return nil
}

func (m *SnapshotManager) Exists(vmName, snapshotName string) bool {
	if m.ExistsFunc != nil {
		return m.ExistsFunc(vmName, snapshotName)
	}
	return false
}

func (m *SnapshotManager) GetInfo(vmName, snapshotName string) (backend.SnapshotInfo, error) {
	if m.GetInfoFunc != nil {
		return m.GetInfoFunc(vmName, snapshotName)
	}
	return backend.SnapshotInfo{Name: snapshotName}, nil
}

// EgressController implements backend.EgressController with configurable function hooks.
type EgressController struct {
	DefineFunc         func(ctx context.Context, inst *config.Instance, p backend.EgressPolicy) error
	ApplyFunc          func(ctx context.Context, inst *config.Instance) error
	RemoveFunc         func(ctx context.Context, inst *config.Instance) error
	VerifyFunc         func(ctx context.Context, inst *config.Instance) (bool, error)
	VerifyEnforcedFunc func(ctx context.Context, inst *config.Instance) (bool, error)
}

func (m *EgressController) Define(ctx context.Context, inst *config.Instance, p backend.EgressPolicy) error {
	if m.DefineFunc != nil {
		return m.DefineFunc(ctx, inst, p)
	}
	return nil
}

func (m *EgressController) Apply(ctx context.Context, inst *config.Instance) error {
	if m.ApplyFunc != nil {
		return m.ApplyFunc(ctx, inst)
	}
	return nil
}

func (m *EgressController) Remove(ctx context.Context, inst *config.Instance) error {
	if m.RemoveFunc != nil {
		return m.RemoveFunc(ctx, inst)
	}
	return nil
}

func (m *EgressController) Verify(ctx context.Context, inst *config.Instance) (bool, error) {
	if m.VerifyFunc != nil {
		return m.VerifyFunc(ctx, inst)
	}
	return false, nil
}

func (m *EgressController) VerifyEnforced(ctx context.Context, inst *config.Instance) (bool, error) {
	if m.VerifyEnforcedFunc != nil {
		return m.VerifyEnforcedFunc(ctx, inst)
	}
	return false, nil
}
