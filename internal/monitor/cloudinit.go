package monitor

import (
	_ "embed"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/sandialabs/abox/internal/cloudinit"
	"github.com/sandialabs/abox/internal/tetragon/policy"
	"github.com/sandialabs/abox/internal/validation"
)

//go:embed templates/monitor-agent.sh
var monitorAgentScript string

//go:embed templates/monitor-agent.service
var monitorAgentService string

//go:embed templates/write-file-monitor-agent.yaml.tmpl
var writeFileMonitorAgentTmpl string

//go:embed templates/write-file-monitor-service.yaml.tmpl
var writeFileMonitorServiceTmpl string

// CloudInitContributor produces cloud-init content for Tetragon monitoring.
type CloudInitContributor struct {
	Enabled         bool     // whether Tetragon monitoring is enabled
	KprobeMulti     bool     // enable BPF kprobe_multi attachment (default false = disabled)
	Kprobes         []string // curated kprobe names (nil = all defaults); used when Policies is nil
	Policies        []string // absolute paths to custom TracingPolicy YAML files
	TetragonTarball string   // path to pre-downloaded Tetragon tarball (required when Enabled)
	TetragonVersion string   // Tetragon version (e.g., "v1.3.0") - validated format required
}

// Contribute returns cloud-init content for Tetragon monitoring.
// Returns nil when monitoring is not enabled.
func (c *CloudInitContributor) Contribute() (*cloudinit.Contribution, error) {
	if !c.Enabled {
		return nil, nil //nolint:nilnil // nil means no contribution when monitoring is disabled
	}

	// Validate Tetragon version for defense-in-depth (used in directory name)
	if err := validation.ValidateTetragonVersion(c.TetragonVersion); err != nil {
		return nil, err
	}

	var writeFiles []string

	// Add monitor agent script and service
	type writeFileData struct{ Content string }
	for _, entry := range []struct{ name, tmpl, content string }{
		{"write-file-monitor-agent", writeFileMonitorAgentTmpl, monitorAgentScript},
		{"write-file-monitor-service", writeFileMonitorServiceTmpl, monitorAgentService},
	} {
		rendered, err := cloudinit.RenderTemplate(entry.name, entry.tmpl, writeFileData{
			Content: cloudinit.IndentLines(entry.content),
		})
		if err != nil {
			return nil, err
		}
		writeFiles = append(writeFiles, strings.TrimRight(rendered, "\n"))
	}

	// Disable kprobe_multi unless explicitly enabled.
	// On some kernels (e.g., 6.8.0-90-generic), kprobe_multi silently fails
	// for a subset of kprobes — they load without error but never fire.
	if !c.KprobeMulti {
		writeFiles = append(writeFiles,
			`  - path: /etc/tetragon/tetragon.conf.d/disable-kprobe-multi
    permissions: '0644'
    content: "true"`)
	}

	// Increase perf ring buffer from default ~65K/CPU to 4MB total.
	// High-frequency kprobes (security_file_open, commit_creds) can saturate
	// the default buffer, causing bpf_perf_event_output to return -ENOSPC
	// and silently dropping events from low-frequency kprobes.
	writeFiles = append(writeFiles,
		`  - path: /etc/tetragon/tetragon.conf.d/rb-size-total
    permissions: '0644'
    content: "4194304"`)

	// Generate tracing policy: either curated kprobes or custom policy files
	if len(c.Policies) > 0 {
		// Custom policy files — embed each one
		for i, policyPath := range c.Policies {
			policyContent, err := os.ReadFile(policyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read monitor policy %s: %w", policyPath, err)
			}
			writeFiles = append(writeFiles,
				fmt.Sprintf(`  - path: /etc/tetragon/tetragon.tp.d/custom-%d.yaml
    permissions: '0644'
    content: |
%s`, i, cloudinit.IndentLines(string(policyContent))))
		}
	} else {
		// Curated kprobes — one TracingPolicy per kprobe for isolation.
		// Tetragon fails an entire policy if any kprobe attachment fails,
		// so per-kprobe policies prevent one broken kprobe from blocking all others.
		policies, err := policy.RenderPerKrobePolicies(c.Kprobes)
		if err != nil {
			return nil, fmt.Errorf("failed to render tracing policies: %w", err)
		}
		filenames := make([]string, 0, len(policies))
		for filename := range policies {
			filenames = append(filenames, filename)
		}
		sort.Strings(filenames)
		for _, filename := range filenames {
			policyYAML := policies[filename]
			writeFiles = append(writeFiles,
				fmt.Sprintf(`  - path: /etc/tetragon/tetragon.tp.d/%s
    permissions: '0644'
    content: |
%s`, filename, cloudinit.IndentLines(string(policyYAML))))
		}
	}

	// Build runcmd items for Tetragon installation
	runcmd := []string{
		"  - mkdir -p /etc/tetragon/tetragon.tp.d",
		fmt.Sprintf(`  - |
    # Mount cidata ISO and install Tetragon from it (ISO piggyback approach)
    # This avoids shell command injection vulnerabilities that would exist
    # if downloading via curl with untrusted version/URL values.
    mkdir -p /mnt/cidata
    mount -o ro /dev/sr0 /mnt/cidata
    cp /mnt/cidata/tetragon.tar.gz /tmp/
    umount /mnt/cidata
    # Extract safely (GNU tar strips leading slashes by default)
    mkdir -p /tmp/tetragon-extract
    tar -xzf /tmp/tetragon.tar.gz -C /tmp/tetragon-extract
    cd /tmp/tetragon-extract/tetragon-%s-amd64 && test -f install.sh && ./install.sh
    rm -rf /tmp/tetragon-extract /tmp/tetragon.tar.gz`, c.TetragonVersion),
		"  - systemctl daemon-reload",
		"  - systemctl enable tetragon",
		"  - systemctl start tetragon",
		"  - systemctl enable abox-monitor",
		"  - systemctl start abox-monitor",
	}

	// Set ISO files for piggyback
	isoFiles := map[string]string{
		"tetragon.tar.gz": c.TetragonTarball,
	}

	return &cloudinit.Contribution{
		WriteFiles: writeFiles,
		Runcmd:     runcmd,
		ISOFiles:   isoFiles,
	}, nil
}
