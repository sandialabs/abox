package helptopics

const yamlHelpText = `abox.yaml Configuration Reference

LOCATION
  abox.yaml in current directory (or specify with -d/--dir)

FIELDS
  version          int      Configuration version (required, must be 1)
  name             string   Instance name (required)
  backend          string   VM backend (default: auto-detect; libvirt on Linux, vfkit on macOS).
                            ABOX_BACKEND overrides it. Experimental backends (vmware) are
                            rejected here; select those with ABOX_BACKEND.
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
    upstream       string   Upstream DNS server (default: host system resolver from /etc/resolv.conf)

  http:                     HTTP proxy configuration object
    mitm           bool     Enable TLS MITM for HTTPS inspection (default: true)
    max_connections int     Cap on concurrent client connections to the proxy (default: 512).
                           Keep below the host's 'ulimit -n'.
    allow_private_targets []string CIDRs the filters may reach despite the default SSRF
                           deny of private/loopback/link-local/metadata IPs (default: none)
    mitm_exceptions []string Domains carried as a transparent TLS tunnel (no interception)
                           even when mitm is enabled, for certificate-pinning apps. Matches
                           the domain and its subdomains. A domain must still be allowlisted
                           to be reachable — an exception only downgrades interception to a
                           tunnel, it never grants access. Keep the list minimal.
    secret_injections []object Bind values from the per-instance secret store into outbound
                           request headers, so the guest never holds the raw credential:
                             key          string  Name in the secret store (required)
                             host         string  Exact host to inject into (required)
                             header       string  Header name to set (required)
                             path_prefix  string  Only inject under this path prefix (default: all)
                             value_prefix string  Prepended to the value (e.g. "Bearer ")
                           A secret_injections host cannot also be a mitm_exceptions domain:
                           injection needs a request to modify. See 'abox secrets --help'.

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
    mitm: true              # Prefer mitm_exceptions over disabling this globally
    # mitm_exceptions:      # Tunnel these without interception (pinned certs)
    #   - pinned.example.com
    # secret_injections:    # Value comes from 'abox secrets set', never from this file
    #   - key: api-key
    #     host: api.anthropic.com
    #     header: x-api-key
  monitor:
    enabled: true
    # version: v1.3.0  # Optional: pin to specific version
  # overrides:                 # Advanced: backend-specific overrides
  #   libvirt:
  #     template: domain.xml.tmpl  # Custom VM template (see 'abox overrides dump libvirt.template')

COMMANDS
  abox init            Generate abox.yaml interactively
  abox up              Create/start/provision from abox.yaml
  abox up --conf-policy Reconcile a diverged allowlist (keep|replace|prompt)
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
