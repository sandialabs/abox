// Package secrets implements the `abox secrets` command group for managing the
// per-instance host-side secret store used by HTTP header injection.
package secrets

import (
	"github.com/sandialabs/abox/pkg/cmd/factory"
	secretslist "github.com/sandialabs/abox/pkg/cmd/secrets/list"
	"github.com/sandialabs/abox/pkg/cmd/secrets/remove"
	"github.com/sandialabs/abox/pkg/cmd/secrets/set"

	"github.com/spf13/cobra"
)

// NewCmdSecrets creates the `abox secrets` parent command.
func NewCmdSecrets(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "Manage host-side secrets injected into outbound requests",
		Long: `Manage per-instance secret values (e.g. API keys) that the HTTP proxy
injects into outbound requests, so the guest never holds the raw credential.

Secret values are stored on the host at 0600 under the instance directory and are
never copied into the VM. Bind a stored key to a host+header via the
'http.secret_injections' section of abox.yaml. Values take effect when the HTTP
filter starts; changing a value on a running instance requires 'abox stop' then
'abox start'.`,
	}

	cmd.AddCommand(set.NewCmdSet(f, nil))
	cmd.AddCommand(secretslist.NewCmdList(f, nil))
	cmd.AddCommand(remove.NewCmdRemove(f, nil))

	return cmd
}
