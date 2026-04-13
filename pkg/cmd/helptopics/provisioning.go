package helptopics

import "github.com/spf13/cobra"

const provisioningHelpText = `Provisioning Scripts Reference

OVERVIEW
  Provision scripts are shell scripts that run as root inside the VM via SSH.
  They execute during the first "abox up" (if defined in abox.yaml) or manually
  via "abox provision <name> -s <script>".

ENVIRONMENT VARIABLES
  The following variables are available in every provision script:

    ABOX_NAME               Instance name (e.g. "dev")
    ABOX_USER               SSH username (e.g. "ubuntu")
    ABOX_IP                 VM IP address (e.g. "10.10.10.50")
    ABOX_GATEWAY            Gateway IP (e.g. "10.10.10.1")
    ABOX_SUBNET             Subnet CIDR (e.g. "10.10.10.0/24")
    ABOX_OVERLAY            Overlay mount point (only set when overlay is used)
    DEBIAN_FRONTEND         Set to "noninteractive" (suppresses dpkg prompts)
    NEEDRESTART_SUSPEND     Set to "1" (prevents needrestart from restarting services)

OVERLAY
  Copy host files into the VM before running scripts:

    abox provision dev -s setup.sh --overlay ./files

  Or in abox.yaml:
    overlay: files/
    provision:
      - setup.sh

  Files are mounted at /tmp/abox/overlay (available as $ABOX_OVERLAY).

PROXY SETUP
  When network filtering is active, HTTP/HTTPS traffic goes through the abox
  proxy. Basic proxy variables (HTTP_PROXY, HTTPS_PROXY) are set automatically.

  For services that need explicit proxy configuration (Docker, containerd, snap),
  run the helper script inside the VM:

    abox-proxy-setup

  This configures APT, Docker, containerd, and snap. It is idempotent and only
  configures installed services. For other services, use:

    http://$ABOX_GATEWAY:8080

TIPS
  - Start scripts with "set -e" so they exit on first failure
  - Add "set -x" for verbose debugging output
  - Use 'sudo -u "$ABOX_USER"' for user-specific operations
  - Scripts only run automatically on the first "abox up"; re-run with:
      abox provision <name> -s <script>
  - Split complex setups into multiple scripts for easier debugging:
      provision:
        - scripts/01-system.sh
        - scripts/02-docker.sh

SEE ALSO
  abox help yaml             abox.yaml configuration reference
  abox help filtering        Network filtering reference
  abox help environment      Host-side environment variables
`

// NewCmdProvisioning creates a help topic command for provisioning scripts.
func NewCmdProvisioning() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "provisioning",
		Short: "Provisioning scripts reference",
		Long:  provisioningHelpText,
	}
	// Set Run to show Long text so command appears in its group (not "Additional help topics")
	cmd.Run = func(cmd *cobra.Command, args []string) {
		cmd.Println(cmd.Long)
	}
	return cmd
}
