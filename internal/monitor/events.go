// Package monitor provides functionality for reading Tetragon events via virtio-serial.
package monitor

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/tetragon/policy"
)

// EventType represents the type of Tetragon event.
type EventType string

const (
	EventTypeExec     EventType = "exec"
	EventTypeFile     EventType = "file"
	EventTypeNetwork  EventType = "net"
	EventTypeSecurity EventType = "security" // security & behavioral kprobes
	EventTypeKprobe   EventType = "kprobe"   // generic kprobe from custom policies
	EventTypeUnknown  EventType = "unknown"
)

// Maximum field lengths for event parsing to prevent unbounded memory allocation.
// These limits are generous but prevent malicious events from using excessive memory.
const (
	maxBinaryLength = 4096  // Max length for binary path
	maxPathLength   = 4096  // Max length for file path
	maxArgsLength   = 65536 // Max length for command arguments (can be long)
	maxCwdLength    = 4096  // Max length for current working directory
	maxDestLength   = 1024  // Max length for network destination
	maxCommLength   = 256   // Max length for command name
)

// Event represents a parsed Tetragon event in a simplified format.
type Event struct {
	Time    time.Time `json:"time"`
	Type    EventType `json:"type"`
	PID     uint32    `json:"pid"`
	Binary  string    `json:"binary,omitempty"`
	Args    string    `json:"args,omitempty"`
	Cwd     string    `json:"cwd,omitempty"`
	Path    string    `json:"path,omitempty"`
	Op      string    `json:"op,omitempty"`
	Dest    string    `json:"dest,omitempty"`
	Proto   string    `json:"proto,omitempty"`
	Comm    string    `json:"comm,omitempty"`
	UID     uint32    `json:"uid,omitempty"`
	RawType string    `json:"raw_type,omitempty"` // original Tetragon event type
}

// TetragonEvent represents the raw Tetragon JSON event structure.
// This is a subset of fields we care about.
type TetragonEvent struct {
	ProcessExec   *ProcessExecEvent   `json:"process_exec,omitempty"`
	ProcessExit   *ProcessExitEvent   `json:"process_exit,omitempty"`
	ProcessKprobe *ProcessKprobeEvent `json:"process_kprobe,omitempty"`
	Time          string              `json:"time,omitempty"`
}

// ProcessExecEvent represents a process execution event.
type ProcessExecEvent struct {
	Process *TetragonProcess `json:"process,omitempty"`
	Parent  *TetragonProcess `json:"parent,omitempty"`
}

// ProcessExitEvent represents a process exit event.
type ProcessExitEvent struct {
	Process *TetragonProcess `json:"process,omitempty"`
}

// ProcessKprobeEvent represents a kprobe event (file/network operations).
type ProcessKprobeEvent struct {
	Process      *TetragonProcess `json:"process,omitempty"`
	FunctionName string           `json:"function_name,omitempty"`
	Args         []KprobeArg      `json:"args,omitempty"`
}

// KprobeArg represents an argument to a kprobe.
type KprobeArg struct {
	FileArg               *FileArg               `json:"file_arg,omitempty"`
	SockArg               *SockArg               `json:"sock_arg,omitempty"`
	SockaddrArg           *SockaddrArg           `json:"sockaddr_arg,omitempty"`
	IntArg                *int64                 `json:"int_arg,omitempty"`
	StringArg             string                 `json:"string_arg,omitempty"`
	LinuxBinprmArg        *LinuxBinprmArg        `json:"linux_binprm_arg,omitempty"`
	ProcessCredentialsArg *ProcessCredentialsArg `json:"process_credentials_arg,omitempty"`
	KernelModuleArg       *KernelModuleArg       `json:"module_arg,omitempty"`
}

// FileArg represents a file argument in a kprobe.
type FileArg struct {
	Path string `json:"path,omitempty"`
}

// LinuxBinprmArg represents a linux_binprm argument in a kprobe (exec check).
type LinuxBinprmArg struct {
	Path       string `json:"path,omitempty"`
	Flags      string `json:"flags,omitempty"`
	Permission string `json:"permission,omitempty"`
}

// ProcessCredentialsArg represents process credentials in a kprobe.
type ProcessCredentialsArg struct {
	UID  *uint32 `json:"uid,omitempty"`
	GID  *uint32 `json:"gid,omitempty"`
	EUID *uint32 `json:"euid,omitempty"`
	EGID *uint32 `json:"egid,omitempty"`
}

// KernelModuleArg represents a kernel module argument in a kprobe.
type KernelModuleArg struct {
	Name string `json:"name,omitempty"`
}

// SockArg represents a socket argument in a kprobe.
type SockArg struct {
	Family   string `json:"family,omitempty"`
	Type     string `json:"type,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Saddr    string `json:"saddr,omitempty"`
	Daddr    string `json:"daddr,omitempty"`
	Sport    uint32 `json:"sport,omitempty"`
	Dport    uint32 `json:"dport,omitempty"`
}

// SockaddrArg represents a socket address argument in a kprobe (e.g., security_socket_connect).
type SockaddrArg struct {
	Family string `json:"family,omitempty"`
	Addr   string `json:"addr,omitempty"`
	Port   uint32 `json:"port,omitempty"`
}

// TetragonProcess represents process information in Tetragon events.
type TetragonProcess struct {
	ExecID       string `json:"exec_id,omitempty"`
	PID          uint32 `json:"pid,omitempty"`
	UID          uint32 `json:"uid,omitempty"`
	Cwd          string `json:"cwd,omitempty"`
	Binary       string `json:"binary,omitempty"`
	Arguments    string `json:"arguments,omitempty"`
	Flags        string `json:"flags,omitempty"`
	StartTime    string `json:"start_time,omitempty"`
	Auid         uint32 `json:"auid,omitempty"`
	Pod          *Pod   `json:"pod,omitempty"`
	Docker       string `json:"docker,omitempty"`
	ParentExecID string `json:"parent_exec_id,omitempty"`
}

// Pod represents Kubernetes pod information (if running in k8s).
type Pod struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}

// truncate truncates a string to the specified max length.
// This prevents unbounded memory allocation from malicious events.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// ParseTetragonEvent parses a raw Tetragon JSON event into our simplified Event format.
func ParseTetragonEvent(data []byte) (*Event, error) {
	var raw TetragonEvent
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse tetragon event: %w", err)
	}

	event := &Event{
		Time: time.Now(), // Default to now if parsing fails
	}

	// Try to parse the time
	if raw.Time != "" {
		if t, err := time.Parse(time.RFC3339Nano, raw.Time); err == nil {
			event.Time = t
		} else {
			logging.Debug("failed to parse event time, using current time", "raw_time", raw.Time, "error", err)
		}
	}

	// Handle different event types
	switch {
	case raw.ProcessExec != nil:
		event.Type = EventTypeExec
		event.RawType = "process_exec"
		if p := raw.ProcessExec.Process; p != nil {
			event.PID = p.PID
			event.UID = p.UID
			event.Binary = truncate(p.Binary, maxBinaryLength)
			event.Args = truncate(p.Arguments, maxArgsLength)
			event.Cwd = truncate(p.Cwd, maxCwdLength)
			event.Comm = truncate(extractComm(p.Binary), maxCommLength)
		}

	case raw.ProcessKprobe != nil:
		kprobe := raw.ProcessKprobe
		event.RawType = kprobe.FunctionName

		if p := kprobe.Process; p != nil {
			event.PID = p.PID
			event.UID = p.UID
			event.Comm = truncate(extractComm(p.Binary), maxCommLength)
		}

		// Classify kprobe using the curated registry
		funcName := kprobe.FunctionName
		curated, ok := policy.Registry[funcName]
		if !ok {
			// Tetragon resolves syscalls to arch-specific names (e.g., __x64_sys_setuid)
			curated, ok = policy.Registry[stripArchPrefix(funcName)]
		}
		if ok {
			event.Type = EventType(curated.EventType)
			event.Op = curated.Op
			switch curated.EventType {
			case policy.EventTypeFile:
				extractFileArgs(kprobe.Args, event)
			case policy.EventTypeNetwork:
				extractNetworkArgs(kprobe.Args, event)
			case policy.EventTypeSecurity:
				extractGenericArgs(kprobe.Args, event)
			default:
				extractGenericArgs(kprobe.Args, event)
			}
		} else {
			event.Type = EventTypeKprobe
			event.Op = kprobe.FunctionName
			extractGenericArgs(kprobe.Args, event)
		}

	case raw.ProcessExit != nil:
		return nil, nil //nolint:nilnil // nil means intentionally skipped event type

	default:
		event.Type = EventTypeUnknown
	}

	return event, nil
}

// extractComm extracts the command name from a binary path.
func extractComm(binary string) string {
	if binary == "" {
		return ""
	}
	parts := strings.Split(binary, "/")
	return parts[len(parts)-1]
}

// stripArchPrefix removes architecture-specific prefixes that Tetragon adds
// when resolving syscall function names (e.g., __x64_sys_setuid → sys_setuid).
func stripArchPrefix(name string) string {
	for _, prefix := range []string{"__x64_", "__ia32_", "__arm64_"} {
		if strings.HasPrefix(name, prefix) {
			return name[len(prefix):]
		}
	}
	return name
}

// extractFileArgs populates event.Path from the first file arg.
func extractFileArgs(args []KprobeArg, event *Event) {
	for _, arg := range args {
		if arg.FileArg != nil {
			event.Path = truncate(arg.FileArg.Path, maxPathLength)
			return
		}
	}
}

// extractNetworkArgs populates event.Proto and event.Dest from the first sock or sockaddr arg.
func extractNetworkArgs(args []KprobeArg, event *Event) {
	for _, arg := range args {
		if arg.SockArg != nil {
			event.Proto = strings.ToLower(arg.SockArg.Protocol)
			if event.Proto == "" {
				event.Proto = "tcp"
			}
			if event.Op == "listen" {
				event.Dest = truncate(fmt.Sprintf(":%d", arg.SockArg.Sport), maxDestLength)
			} else {
				event.Dest = truncate(fmt.Sprintf("%s:%d", arg.SockArg.Daddr, arg.SockArg.Dport), maxDestLength)
			}
			return
		}
		if arg.SockaddrArg != nil {
			event.Proto = "tcp"
			event.Dest = truncate(fmt.Sprintf("%s:%d", arg.SockaddrArg.Addr, arg.SockaddrArg.Port), maxDestLength)
			return
		}
	}
}

// extractGenericArgs populates event fields from any kprobe arg types.
// Used for security kprobes, custom policy kprobes, and any future event types.
// If a linux_binprm or file arg is found, its path goes to event.Path.
// All other args are formatted into event.Args.
func extractGenericArgs(args []KprobeArg, event *Event) {
	var parts []string
	for _, arg := range args {
		switch {
		case arg.LinuxBinprmArg != nil:
			event.Path = truncate(arg.LinuxBinprmArg.Path, maxPathLength)
		case arg.FileArg != nil:
			parts = append(parts, truncate(arg.FileArg.Path, maxPathLength))
		case arg.SockArg != nil:
			parts = append(parts, truncate(fmt.Sprintf("%s:%d->%s:%d", arg.SockArg.Saddr, arg.SockArg.Sport, arg.SockArg.Daddr, arg.SockArg.Dport), maxDestLength))
		case arg.ProcessCredentialsArg != nil:
			if arg.ProcessCredentialsArg.UID != nil {
				parts = append(parts, fmt.Sprintf("uid=%d", *arg.ProcessCredentialsArg.UID))
			}
			if arg.ProcessCredentialsArg.EUID != nil {
				parts = append(parts, fmt.Sprintf("euid=%d", *arg.ProcessCredentialsArg.EUID))
			}
		case arg.KernelModuleArg != nil:
			parts = append(parts, truncate(arg.KernelModuleArg.Name, maxCommLength))
		case arg.IntArg != nil:
			parts = append(parts, strconv.FormatInt(*arg.IntArg, 10))
		case arg.StringArg != "":
			parts = append(parts, truncate(arg.StringArg, maxPathLength))
		}
	}
	if len(parts) > 0 {
		event.Args = truncate(strings.Join(parts, " "), maxArgsLength)
	}
}
