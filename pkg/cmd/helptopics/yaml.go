package helptopics

const yamlHelpText = `abox.yaml Configuration Reference

LOCATION
  abox.yaml in current directory (or specify with -d/--dir)

FIELDS
  version          int      Configuration version (required, must be 1)
  name             string   Instance name (required)
  backend          string   VM backend (default: auto-detect, currently only "libvirt")
  cpus             int      CPU cores (default: 2)
  memory           int      Memory in MB (default: 4096)
  disk             string   Disk size (default: "20G")
  base             string   Base image (default: "ubuntu-24.04")
  user             string   SSH username (default: auto-detected from base image)
  subnet           string   Custom /24 subnet, auto-allocated if not specified
  provision        []string Paths to provision scripts
  overlay          string   Directory to copy into VM at /tmp/abox/overlay
  allowlist        []string Domain allowlist entries (shared by DNS and HTTP filters)

  dns:                      DNS configuration object
    upstream       string   Upstream DNS server (default: "8.8.8.8:53")

  http:                     HTTP proxy configuration object
    mitm           bool     Enable TLS MITM for HTTPS inspection (default: true)

  monitor:                  Agent monitoring configuration
    enabled        bool     Enable Tetragon monitoring via virtio-serial (default: false)
    version        string   Tetragon version to use (empty = latest, e.g., "v1.3.0")
    kprobe_multi   bool     Enable BPF kprobe_multi attachment (default: false)
    kprobes        []string Curated kprobe names (nil = all defaults; mutually exclusive with policies)
    policies       []string Paths to custom TracingPolicy YAML files (mutually exclusive with kprobes)

  overrides:                Backend-specific overrides (advanced)
    libvirt:                Libvirt backend overrides
      template   string    Path to custom domain XML template (Go text/template)

MINIMAL EXAMPLE
  version: 1
  name: dev

FULL EXAMPLE
  version: 1
  name: dev
  cpus: 4
  memory: 8192
  disk: "40G"
  base: ubuntu-24.04
  # user: ubuntu  (auto-detected from base image if not set)
  subnet: "10.10.20.0/24"
  provision:
    - ./scripts/setup.sh
  overlay: files/
  allowlist:
    - "*.github.com"
    - "*.anthropic.com"
  dns:
    upstream: "1.1.1.1:53"
  http:
    mitm: true              # Disable with false for certificate-pinning apps
  monitor:
    enabled: true
    # version: v1.3.0  # Optional: pin to specific version
  # overrides:                 # Advanced: backend-specific overrides
  #   libvirt:
  #     template: domain.xml.tmpl  # Custom VM template (see 'abox overrides dump libvirt.template')

COMMANDS
  abox init            Generate abox.yaml interactively
  abox up              Create/start/provision from abox.yaml
  abox down            Stop instance
  abox down --remove   Stop and delete instance
  abox monitor logs <name>    View Tetragon monitoring events (requires monitor.enabled: true)
  abox monitor status <name>  Check monitor status

SEE ALSO
  abox init --help
  abox up --help
  abox down --help
  abox monitor logs --help
`
