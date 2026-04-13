package helptopics

const quickstartHelpText = `Quick Start Guide

PREREQUISITES
  - libvirt/QEMU installed and running
  - User in libvirt group
  - iptables available

  Check with: abox check-deps

GET A BASE IMAGE
  abox base pull ubuntu-24.04    # Or any image from 'abox base list'
  abox base list                 # See available images (Ubuntu, AlmaLinux, Debian)
  abox base remove ubuntu-24.04  # Remove a downloaded base image

IMPERATIVE WORKFLOW
  # Create and start
  abox create dev --cpus 2 --memory 4096
  abox start dev
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
  abox mount dev ~/mnt   # Mount instance via SSHFS

SEE ALSO
  abox help yaml             abox.yaml configuration reference
  abox help filtering        Network filtering reference
  abox help provisioning     Provisioning scripts reference
  abox --help                All commands
`
