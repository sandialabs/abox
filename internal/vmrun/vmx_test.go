package vmrun

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/config"
)

func testInstance() *config.Instance {
	return &config.Instance{
		Name:       "dev",
		Base:       "ubuntu-24.04",
		CPUs:       4,
		Memory:     8192,
		Bridge:     "vmnet7",
		MACAddress: "00:0c:29:ab:cd:ef",
	}
}

func testPaths(t *testing.T) *config.Paths {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	p, err := config.GetPaths("dev")
	if err != nil {
		t.Fatalf("GetPaths: %v", err)
	}
	return p
}

func TestGenerateVMX_Contents(t *testing.T) {
	inst := testInstance()
	paths := testPaths(t)

	out, err := GenerateVMX(inst, paths, VMXOptions{AssumeCloudInitExists: true})
	if err != nil {
		t.Fatalf("GenerateVMX: %v", err)
	}

	wantContains := []string{
		`ethernet0.connectionType = "hostonly"`,
		`ethernet0.vnet = "vmnet7"`,
		`ethernet0.address = "00:0c:29:ab:cd:ef"`,
		`ethernet0.virtualDev = "vmxnet3"`,
		`scsi0:0.fileName = "disk.vmdk"`,
		`scsi0.virtualDev = "lsilogic"`,
		`memsize = "8192"`,
		`numvcpus = "4"`,
		`guestOS = "ubuntu-64"`,
		`displayName = "dev"`,
		`ide1:0.deviceType = "cdrom-image"`,
		`ide1:0.fileName = "cidata.iso"`,
		`uuid.bios = "`,
		`msg.autoAnswer = "TRUE"`,
	}
	for _, w := range wantContains {
		if !strings.Contains(out, w) {
			t.Errorf("vmx missing %q\n---\n%s", w, out)
		}
	}
}

func TestGenerateVMX_NoCloudInit(t *testing.T) {
	inst := testInstance()
	paths := testPaths(t)

	// AssumeCloudInitExists=false and the ISO does not exist -> no CDROM lines.
	out, err := GenerateVMX(inst, paths, VMXOptions{AssumeCloudInitExists: false})
	if err != nil {
		t.Fatalf("GenerateVMX: %v", err)
	}
	if strings.Contains(out, "ide1:0") || strings.Contains(out, "cdrom-image") {
		t.Errorf("vmx should not contain cloud-init CDROM lines when ISO absent:\n%s", out)
	}
}

func TestGenerateVMX_PreservesUUID(t *testing.T) {
	inst := testInstance()
	paths := testPaths(t)

	const uuid = "56 4d aa bb cc dd ee ff-00 11 22 33 44 55 66 77"
	out, err := GenerateVMX(inst, paths, VMXOptions{UUID: uuid})
	if err != nil {
		t.Fatalf("GenerateVMX: %v", err)
	}
	if !strings.Contains(out, `uuid.bios = "`+uuid+`"`) {
		t.Errorf("uuid.bios not preserved; want %q\n%s", uuid, out)
	}
	if !strings.Contains(out, `uuid.location = "`+uuid+`"`) {
		t.Errorf("uuid.location not preserved; want %q\n%s", uuid, out)
	}
}

func TestGenerateVMX_GeneratesUUIDWhenEmpty(t *testing.T) {
	inst := testInstance()
	paths := testPaths(t)

	out, err := GenerateVMX(inst, paths, VMXOptions{})
	if err != nil {
		t.Fatalf("GenerateVMX: %v", err)
	}
	// Two independent generations must differ (random UUID).
	out2, _ := GenerateVMX(inst, paths, VMXOptions{})
	if extractUUID(t, out) == extractUUID(t, out2) {
		t.Error("expected distinct generated UUIDs across calls")
	}
	if extractUUID(t, out) == "" {
		t.Error("expected a non-empty generated uuid.bios")
	}
}

func TestGenerateVMX_MonitorSerialPipe(t *testing.T) {
	inst := testInstance()
	paths := testPaths(t)

	out, err := GenerateVMX(inst, paths, VMXOptions{MonitorEnabled: true})
	if err != nil {
		t.Fatalf("GenerateVMX: %v", err)
	}

	// The serial pipe binds VMware (as a pipe server) to the instance's monitor
	// socket by ABSOLUTE path — monitor.sock lives outside DiskDir.
	wantContains := []string{
		`serial0.present = "TRUE"`,
		`serial0.fileType = "pipe"`,
		`serial0.fileName = "` + paths.MonitorSocket + `"`,
		`serial0.pipe.endPoint = "server"`,
		`serial0.tryNoRxLoss = "FALSE"`,
		// yieldOnMsrRead avoids burning a host CPU polling the pipe.
		`serial0.yieldOnMsrRead = "TRUE"`,
	}
	for _, w := range wantContains {
		if !strings.Contains(out, w) {
			t.Errorf("vmx missing %q\n---\n%s", w, out)
		}
	}

	// The pipe fileName must be ABSOLUTE: monitor.sock lives outside DiskDir, so
	// (unlike the vmdk/ISO) it cannot be referenced by basename.
	if !filepath.IsAbs(paths.MonitorSocket) {
		t.Fatalf("test precondition: MonitorSocket not absolute: %q", paths.MonitorSocket)
	}
}

func TestGenerateVMX_NoMonitorNoSerial(t *testing.T) {
	inst := testInstance()
	paths := testPaths(t)

	out, err := GenerateVMX(inst, paths, VMXOptions{MonitorEnabled: false})
	if err != nil {
		t.Fatalf("GenerateVMX: %v", err)
	}
	if strings.Contains(out, "serial0.") {
		t.Errorf("expected no serial device when monitoring disabled:\n%s", out)
	}
}

func TestGenerateVMX_RejectsBadName(t *testing.T) {
	inst := testInstance()
	inst.Name = "bad name!"
	paths := testPaths(t)
	if _, err := GenerateVMX(inst, paths, VMXOptions{}); err == nil {
		t.Error("expected error for invalid instance name")
	}
}

func TestGenerateVMX_RejectsBadMAC(t *testing.T) {
	inst := testInstance()
	inst.MACAddress = "not-a-mac"
	paths := testPaths(t)
	if _, err := GenerateVMX(inst, paths, VMXOptions{}); err == nil {
		t.Error("expected error for invalid MAC address")
	}
}

func TestGenerateVMX_RejectsBadVNet(t *testing.T) {
	inst := testInstance()
	inst.BackendConfig = map[string]any{VNetConfigKey: "notvmnet"}
	paths := testPaths(t)
	if _, err := GenerateVMX(inst, paths, VMXOptions{}); err == nil {
		t.Error("expected error for non-vmnet vnet")
	}
}

func TestGenerateVMX_RejectsVNetInjection(t *testing.T) {
	inst := testInstance()
	inst.BackendConfig = map[string]any{VNetConfigKey: `vmnet1"` + "\n" + `foo = "bar`}
	paths := testPaths(t)
	if _, err := GenerateVMX(inst, paths, VMXOptions{}); err == nil {
		t.Error("expected error for vnet that breaks out of the quoted field")
	}
}

func TestGenerateVMX_RejectsBackendConfigInjection(t *testing.T) {
	inst := testInstance()
	// Valid vnet so the failure is attributable to the general BackendConfig guard.
	inst.BackendConfig = map[string]any{
		VNetConfigKey: "vmnet5",
		"custom":      "has\"quote",
	}
	paths := testPaths(t)
	if _, err := GenerateVMX(inst, paths, VMXOptions{}); err == nil {
		t.Error("expected error for BackendConfig value containing a quote")
	}
}

func TestGenerateVMX_FirmwareDefaultsBIOS(t *testing.T) {
	inst := testInstance()
	paths := testPaths(t)
	out, err := GenerateVMX(inst, paths, VMXOptions{})
	if err != nil {
		t.Fatalf("GenerateVMX: %v", err)
	}
	if !strings.Contains(out, `firmware = "bios"`) {
		t.Errorf("expected BIOS firmware default:\n%s", out)
	}
	if strings.Contains(out, `firmware = "efi"`) {
		t.Errorf("should not default to EFI:\n%s", out)
	}
}

func TestGenerateVMX_FirmwareEFIOverride(t *testing.T) {
	inst := testInstance()
	inst.BackendConfig = map[string]any{"firmware": "EFI"}
	paths := testPaths(t)
	out, err := GenerateVMX(inst, paths, VMXOptions{})
	if err != nil {
		t.Fatalf("GenerateVMX: %v", err)
	}
	if !strings.Contains(out, `firmware = "efi"`) {
		t.Errorf("expected EFI override to apply:\n%s", out)
	}
}

func TestGenerateVMX_FirmwareUnknownFallsBackBIOS(t *testing.T) {
	inst := testInstance()
	inst.BackendConfig = map[string]any{"firmware": "nonsense"}
	paths := testPaths(t)
	out, err := GenerateVMX(inst, paths, VMXOptions{})
	if err != nil {
		t.Fatalf("GenerateVMX: %v", err)
	}
	if !strings.Contains(out, `firmware = "bios"`) {
		t.Errorf("unknown firmware value should fall back to BIOS:\n%s", out)
	}
}

func TestGenerateVMX_VNetFromBackendConfig(t *testing.T) {
	inst := testInstance()
	inst.Bridge = "abox-dev" // logical name; must be overridden by BackendConfig
	inst.BackendConfig = map[string]any{VNetConfigKey: "vmnet5"}
	paths := testPaths(t)

	out, err := GenerateVMX(inst, paths, VMXOptions{})
	if err != nil {
		t.Fatalf("GenerateVMX: %v", err)
	}
	if !strings.Contains(out, `ethernet0.vnet = "vmnet5"`) {
		t.Errorf("expected ethernet0.vnet from BackendConfig[vnet]:\n%s", out)
	}
	if strings.Contains(out, `ethernet0.vnet = "abox-dev"`) {
		t.Errorf("BackendConfig[vnet] should override inst.Bridge:\n%s", out)
	}
}

func TestGenerateVMX_VNetFallsBackToBridge(t *testing.T) {
	inst := testInstance()
	inst.Bridge = "vmnet7" // no BackendConfig[vnet] set
	paths := testPaths(t)

	out, err := GenerateVMX(inst, paths, VMXOptions{})
	if err != nil {
		t.Fatalf("GenerateVMX: %v", err)
	}
	if !strings.Contains(out, `ethernet0.vnet = "vmnet7"`) {
		t.Errorf("expected ethernet0.vnet to fall back to inst.Bridge:\n%s", out)
	}
}

func TestGenerateVMX_VNetEmptyStringFallsBack(t *testing.T) {
	inst := testInstance()
	inst.Bridge = "vmnet7"
	inst.BackendConfig = map[string]any{VNetConfigKey: ""} // empty -> ignore
	paths := testPaths(t)

	out, err := GenerateVMX(inst, paths, VMXOptions{})
	if err != nil {
		t.Fatalf("GenerateVMX: %v", err)
	}
	if !strings.Contains(out, `ethernet0.vnet = "vmnet7"`) {
		t.Errorf("empty BackendConfig[vnet] should fall back to inst.Bridge:\n%s", out)
	}
}

func TestGuestOSForBase(t *testing.T) {
	cases := []struct {
		base string
		want string
	}{
		{"ubuntu-24.04", "ubuntu-64"},
		{"ubuntu", "ubuntu-64"},
		{"debian-12", "debian12-64"},
		{"almalinux-9", "rhel9-64"},
		{"rhel-9", "rhel9-64"},
		{"rocky-9", "rhel9-64"},
		{"centos-9", "rhel9-64"},
		{"gentoo", "otherlinux-64"},
		{"", "otherlinux-64"},
	}
	for _, c := range cases {
		if got := GuestOSForBase(c.base); got != c.want {
			t.Errorf("GuestOSForBase(%q)=%q want %q", c.base, got, c.want)
		}
	}
}

func TestVMXPath(t *testing.T) {
	paths := testPaths(t)
	got := VMXPath(paths)
	if !strings.HasSuffix(got, "disk.vmx") {
		t.Errorf("VMXPath=%q want suffix disk.vmx", got)
	}
	if !strings.HasPrefix(got, paths.DiskDir) {
		t.Errorf("VMXPath=%q should be under DiskDir %q", got, paths.DiskDir)
	}
}

// extractUUID returns the uuid.bios value from generated vmx text.
func extractUUID(t *testing.T, vmx string) string {
	t.Helper()
	const key = `uuid.bios = "`
	_, rest, ok := strings.Cut(vmx, key)
	if !ok {
		return ""
	}
	val, _, ok := strings.Cut(rest, `"`)
	if !ok {
		return ""
	}
	return val
}
