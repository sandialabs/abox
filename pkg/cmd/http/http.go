package http

import (
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/http/level"
	"github.com/sandialabs/abox/pkg/cmd/http/logs"
	"github.com/sandialabs/abox/pkg/cmd/http/serve"
	httpstatus "github.com/sandialabs/abox/pkg/cmd/http/status"

	"github.com/spf13/cobra"
)

// NewCmdHTTP creates a new http command.
func NewCmdHTTP(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "http",
		Short: "Manage HTTP proxy filter",
		Long:  `Manage the HTTP proxy filter for an instance.`,
	}

	cmd.AddCommand(level.NewCmdLevel(f))
	cmd.AddCommand(httpstatus.NewCmdStatus(f, nil))
	cmd.AddCommand(logs.NewCmdLogs(f))
	cmd.AddCommand(serve.NewCmdServe(f, nil))

	return cmd
}
