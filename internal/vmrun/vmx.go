package vmrun

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/validation"
)

// vmxTemplate is the Go text/template for a VMware .vmx configuration file.
//
// Device choices (documented for real-host validation):
//   - scsi0.virtualDev="lsilogic": the LSI Logic parallel controller is the most
//     broadly supported virtual SCSI adapter across guest kernels without extra
//     drivers. pvscsi is faster but needs VMware Tools/paravirtual drivers in the
//     guest, which our cloud images do not guarantee at first boot; lsilogic is
//     the safe default. TODO(real-host): consider pvscsi once Tools presence is
//     guaranteed.
//   - ethernet0.virtualDev="vmxnet3": vmxnet3 is the modern paravirtual NIC and
//     is supported out-of-the-box by current Linux kernels (in-tree vmxnet3
//     driver), giving better throughput than e1000e. TODO(real-host): fall back
//     to e1000e if a target guest lacks the vmxnet3 driver.
//   - ide1:0 CDROM (cdrom-image): the cloud-init seed ISO is attached on the IDE
//     bus for maximum guest compatibility at first boot (SATA/AHCI also works but
//     IDE avoids any AHCI driver dependency in minimal images).
//   - firmware="bios": abox base images are qemu-converted cloud images that are
//     most reliably BIOS/MBR-bootable; an EFI-firmware VM may fail to boot them.
//     BIOS is the safe default. TODO(real-host): confirm firmware per base image
//     and make it overridable (already wired through inst.BackendConfig["firmware"]).
//   - serial0 pipe (MonitorEnabled only): the Tetragon monitor transport. VMware
//     has no virtio-serial, so monitoring rides a serial port exposed as a pipe.
//     endPoint="server" makes VMware create and listen on a Unix socket at
//     MonitorSocket when the VM powers on; the (unchanged) monitor daemon dials
//     that socket exactly as it dials libvirt's. tryNoRxLoss="FALSE" keeps the VM
//     from stalling when no reader is connected. yieldOnMsrRead="TRUE" avoids
//     burning a host CPU while polling the pipe. The
//     guest sees this as /dev/ttyS0 (see
//     internal/backend/vmware.monitorGuestDevice). TODO(real-host): if a base
//     image sets console=ttyS0, move the pipe to serial1 (/dev/ttyS1) so kernel
//     console output does not corrupt the event stream; and confirm the socket
//     VMware creates is accessible to the user-run monitor daemon.
//
// Hardening/quiet defaults: msg.autoAnswer suppresses interactive prompts (so
// vmrun never blocks), and shared folders / drag-and-drop / copy-paste are
// disabled to reduce the host<->guest surface for an untrusted agent VM.
const vmxTemplate = `.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "19"
displayName = "{{.DisplayName}}"
guestOS = "{{.GuestOS}}"
memsize = "{{.Memory}}"
numvcpus = "{{.CPUs}}"
firmware = "{{.Firmware}}"

scsi0.present = "TRUE"
scsi0.virtualDev = "lsilogic"
scsi0:0.present = "TRUE"
scsi0:0.fileName = "{{.DiskFileName}}"
scsi0:0.deviceType = "scsi-hardDisk"
{{- if .CloudInitISO}}

ide1:0.present = "TRUE"
ide1:0.deviceType = "cdrom-image"
ide1:0.fileName = "{{.CloudInitISO}}"
ide1:0.startConnected = "TRUE"
{{- end}}

ethernet0.present = "TRUE"
ethernet0.connectionType = "hostonly"
ethernet0.vnet = "{{.Bridge}}"
ethernet0.addressType = "static"
ethernet0.address = "{{.MACAddress}}"
ethernet0.virtualDev = "vmxnet3"
ethernet0.startConnected = "TRUE"

uuid.action = "keep"
uuid.bios = "{{.UUID}}"
uuid.location = "{{.UUID}}"

msg.autoAnswer = "TRUE"
isolation.tools.hgfs.disable = "TRUE"
isolation.tools.dnd.disable = "TRUE"
isolation.tools.copy.disable = "TRUE"
isolation.tools.paste.disable = "TRUE"
mks.enable3d = "FALSE"
tools.syncTime = "FALSE"
{{- if .MonitorEnabled}}

serial0.present = "TRUE"
serial0.fileType = "pipe"
serial0.fileName = "{{.MonitorSocket}}"
serial0.startConnected = "TRUE"
serial0.pipe.endPoint = "server"
serial0.tryNoRxLoss = "FALSE"
serial0.yieldOnMsrRead = "TRUE"
{{- end}}
`

// VMXData holds the fields substituted into the .vmx template.
type VMXData struct {
	DisplayName    string
	GuestOS        string
	Firmware       string
	Memory         int
	CPUs           int
	DiskFileName   string
	CloudInitISO   string
	Bridge         string
	MACAddress     string
	UUID           string
	MonitorEnabled bool
	MonitorSocket  string
}

// Firmware values accepted by VMware's .vmx (and by firmwareForInstance).
const (
	firmwareBIOS = "bios"
	firmwareEFI  = "efi"
)

// firmwareForInstance selects the .vmx firmware value. It defaults to BIOS (the
// safe default for abox's qemu-converted cloud images) but honors an override in
// inst.BackendConfig["firmware"] of "efi" (any other/absent value keeps BIOS).
// TODO(real-host): confirm which base images actually require EFI.
func firmwareForInstance(inst *config.Instance) string {
	if s, ok := inst.BackendString(config.BackendKeyFirmware); ok && strings.EqualFold(s, firmwareEFI) {
		return firmwareEFI
	}
	return firmwareBIOS
}

// vnetForInstance selects the value emitted as ethernet0.vnet in the .vmx.
//
// VMware host-only networks are identified by a vmnet NUMBER (vmnetN), not by an
// arbitrary bridge name the way libvirt networks are. The NetworkManager
// allocates a free vmnetN per instance (see internal/vmrun.Registry) and
// persists it in inst.BackendConfig["vnet"] (e.g. "vmnet2"). When present, that
// value is authoritative and is what the NIC must reference.
//
// It falls back to inst.Bridge when no vnet is recorded. This keeps generation
// backward-compatible: dry-run and any pre-allocation path (e.g. a test instance
// whose Bridge is already "vmnetN") still render a usable NIC line. The
// NetworkManager is responsible for putting the real, allocated vmnet into
// BackendConfig before the VM is defined.
func vnetForInstance(inst *config.Instance) string {
	if s, ok := inst.BackendString(VNetConfigKey); ok && s != "" {
		return s
	}
	return inst.Bridge
}

// VMXOptions holds options for VMX generation, mirroring backend.VMCreateOptions
// but without importing the backend package (which would create an import cycle:
// the backend depends on this package). The backend adapter copies its options
// into this struct.
type VMXOptions struct {
	// AssumeCloudInitExists forces inclusion of the cloud-init CDROM device even
	// if the ISO file doesn't exist yet (used by dry-run).
	AssumeCloudInitExists bool

	// MonitorEnabled emits the serial-pipe monitor device (serial0 as a pipe
	// server bound to MonitorSocket) that the Tetragon monitor daemon reads from.
	// See the serial0 block in vmxTemplate.
	MonitorEnabled bool

	// UUID is the existing VM UUID to preserve when redefining. Empty string
	// causes a fresh VMware-format UUID to be generated.
	UUID string
}

// GuestOSForBase maps an abox base image name to a VMware guestOS identifier.
//
// Defaults (documented):
//   - ubuntu-*            -> "ubuntu-64"
//   - debian-*            -> "debian12-64"
//   - almalinux-*/rhel-*/rocky-*/centos-* -> "rhel9-64"
//   - anything else       -> "otherlinux-64"
//
// These are 64-bit guest ids; abox base images are all x86_64. The exact id only
// affects VMware's optimization hints, not correctness, so an approximate match
// (e.g. rhel9-64 for a rocky/centos guest) is fine.
func GuestOSForBase(base string) string {
	switch {
	case strings.HasPrefix(base, "ubuntu"):
		return guestOSUbuntu
	case strings.HasPrefix(base, "debian"):
		return "debian12-64"
	case strings.HasPrefix(base, "almalinux"),
		strings.HasPrefix(base, "rhel"),
		strings.HasPrefix(base, "rocky"),
		strings.HasPrefix(base, "centos"):
		return guestOSRHEL
	default:
		return guestOSOther
	}
}

// VMware guestOS identifiers abox emits (64-bit; base images are all x86_64).
const (
	guestOSUbuntu = "ubuntu-64"
	guestOSRHEL   = "rhel9-64"
	guestOSOther  = "otherlinux-64"
)

// VMXPath returns the path of an instance's .vmx file. It lives beside the disk
// in DiskDir as "disk.vmx", so the .vmx can reference the vmdk/ISO by basename.
// Using a fixed name (rather than "<name>.vmx") keeps path derivation trivial:
// callers that only have DiskDir can locate it without the instance name.
func VMXPath(paths *config.Paths) string {
	return filepath.Join(paths.DiskDir, "disk.vmx")
}

// GenerateVMX renders the .vmx configuration for an instance. The generated file
// is meant to live at VMXPath(paths) (beside disk.vmdk / cidata.iso in DiskDir),
// so device fileNames are basenames, not absolute paths.
func GenerateVMX(inst *config.Instance, paths *config.Paths, opts VMXOptions) (string, error) {
	if err := ValidateInstanceForVMX(inst); err != nil {
		return "", err
	}

	cloudInit := ""
	if paths.CloudInitISO != "" && opts.AssumeCloudInitExists {
		// The .vmx sits in DiskDir next to the ISO, so reference it by basename.
		cloudInit = filepath.Base(paths.CloudInitISO)
	}

	uuid := opts.UUID
	if uuid == "" {
		u, err := generateVMwareUUID()
		if err != nil {
			return "", fmt.Errorf("failed to generate uuid: %w", err)
		}
		uuid = u
	}

	// When monitoring is enabled the serial pipe binds VMware to the instance's
	// monitor socket. It must be an absolute path: monitor.sock lives in the
	// instance dir, which can be a different tree from DiskDir (custom/legacy
	// storage), so it cannot be referenced by basename like the vmdk/ISO.
	monitorSocket := ""
	if opts.MonitorEnabled {
		monitorSocket = paths.MonitorSocket
	}

	data := VMXData{
		DisplayName:    inst.Name,
		GuestOS:        GuestOSForBase(inst.Base),
		Firmware:       firmwareForInstance(inst),
		Memory:         inst.Memory,
		CPUs:           inst.CPUs,
		DiskFileName:   filepath.Base(InstanceVMDKPath(paths.DiskDir)),
		CloudInitISO:   cloudInit,
		Bridge:         vnetForInstance(inst),
		MACAddress:     inst.MACAddress,
		UUID:           uuid,
		MonitorEnabled: opts.MonitorEnabled,
		MonitorSocket:  monitorSocket,
	}

	t, err := template.New("vmx").Parse(vmxTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse vmx template: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute vmx template: %w", err)
	}
	return buf.String(), nil
}

// safeVNet matches VMware host-only interface names (e.g. "vmnet2"). The
// resolved vnet is emitted verbatim into ethernet0.vnet, so it must match this
// exactly — anything else could break out of the quoted .vmx field.
var safeVNet = regexp.MustCompile(`^vmnet[0-9]+$`)

// ValidateInstanceForVMX validates the instance fields that are interpolated into
// the .vmx. The .vmx is a quoted key="value" text format; a value containing a
// double-quote or newline could break out of its field. Name/MAC are validated
// with the shared validators (which reject such characters) mirroring the domain
// XML path. The resolved vnet (from BackendConfig["vnet"], else inst.Bridge) is
// validated against ^vmnet[0-9]+$, the firmware value is constrained by
// firmwareForInstance to "bios"/"efi", and every BackendConfig string value is
// checked for a double-quote or newline that would break the quoted .vmx field.
func ValidateInstanceForVMX(inst *config.Instance) error {
	if err := validation.ValidateInstanceName(inst.Name); err != nil {
		return fmt.Errorf("invalid instance name: %w", err)
	}
	if err := validation.ValidateMACAddress(inst.MACAddress); err != nil {
		return fmt.Errorf("invalid MAC address: %w", err)
	}
	if v := vnetForInstance(inst); !safeVNet.MatchString(v) {
		return fmt.Errorf("invalid vnet %q: must be a VMware vmnet name (vmnetN)", v)
	}
	// Defense-in-depth: BackendConfig is a free-form map[string]any that
	// config.Instance.Validate does not check. Reject any string value carrying a
	// character that would break out of a quoted .vmx value.
	for k, v := range inst.BackendConfig {
		if s, ok := v.(string); ok && strings.ContainsAny(s, "\"\n\r") {
			return fmt.Errorf("BackendConfig[%q] contains a character that is unsafe in a .vmx value", k)
		}
	}
	return nil
}

// generateVMwareUUID returns a UUID in VMware's uuid.bios format: 16
// space-separated lowercase hex bytes with a dash between the first and second
// groups of 8 (e.g. "56 4d 1a 2b 3c 4d 5e 6f-70 81 92 a3 b4 c5 d6 e7"). VMware
// writes this form; generating it ourselves keeps a stable identity across Redefine.
func generateVMwareUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	parts := make([]string, 16)
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts[:8], " ") + "-" + strings.Join(parts[8:], " "), nil
}
