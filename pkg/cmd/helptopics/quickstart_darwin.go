//go:build darwin

package helptopics

const quickstartHelpText = `Quick Start Guide (macOS)

PREREQUISITES
  - macOS on Apple Silicon (arm64)
  - vfkit, qemu, xorriso installed via Homebrew
      brew install vfkit qemu xorriso
  - macFUSE + sshfs-mac for 'abox mount' (optional)
      brew install --cask macfuse
      brew install gromgit/fuse/sshfs-mac
  - sudo available (first 'abox start' wires abox anchors into /etc/pf.conf)

  Check with: abox check-deps

GET A BASE IMAGE
  abox base pull ubuntu-24.04    # Downloads the arm64 cloud image
  abox base list                 # See available images (Ubuntu, AlmaLinux, Debian)
  abox base remove ubuntu-24.04  # Remove a downloaded base image

IMPERATIVE WORKFLOW
  # Create and start
  abox create dev --cpus 2 --memory 4096
  abox start dev                 # Prompts for sudo (privilege helper + pfctl)
  abox ssh dev

  # Filter modes
  abox net filter dev active   # Block domains not allowed (default)
  abox net filter dev passive  # Allow all, capture domains
  abox net profile dev show    # View captured domains

  # Allowlist
  abox allowlist add dev github.com
  abox allowlist add dev golang.org
  abox allowlist list dev

  # Cleanup
  abox stop dev
  abox remove dev

DECLARATIVE WORKFLOW (recommended)
  Create abox.yaml:
    name: dev
    cpus: 2
    memory: 4096
    allowlist:
      - github.com
      - golang.org
    provision:
      - ./setup.sh

  Then:
    abox up              # Create/start/provision
    abox ssh dev         # Access the instance
    abox down            # Stop
    abox down --remove   # Stop and delete

COMMON TASKS
  abox list              # List all instances
  abox status dev        # Show instance status
  abox scp dev:file .    # Copy file from instance
  abox mount dev ~/mnt   # Mount instance via SSHFS (requires macFUSE)

MACOS-SPECIFIC NOTES
  - 'abox doctor' reports whether abox's PF anchor references are wired
    into /etc/pf.conf. The first 'abox start' adds them automatically.
  - 'abox teardown-pf' removes the anchor references (run before uninstall).
  - monitor.enabled: true is not supported on macOS (Tetragon is Linux-only).
  - Snapshots are not supported by the vfkit backend.

SEE ALSO
  abox help yaml             abox.yaml configuration reference
  abox help filtering        Network filtering reference
  abox help provisioning     Provisioning scripts reference
  abox --help                All commands
`
