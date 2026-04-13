package helper

import (
	"fmt"

	"github.com/sandialabs/abox/internal/privilege"

	"github.com/spf13/cobra"
)

// NewCmdHelper creates a hidden helper command for privilege escalation.
func NewCmdHelper() *cobra.Command {
	var socketPath string
	var allowedUID int

	cmd := &cobra.Command{
		Use:    "privilege-helper",
		Short:  "Internal privileged helper (do not run directly)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := privilege.ValidateSocketPath(socketPath); err != nil {
				return fmt.Errorf("--socket: %w", err)
			}
			return privilege.RunHelper(socketPath, allowedUID)
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", "", "Unix socket path for gRPC server")
	cmd.Flags().IntVar(&allowedUID, "allowed-uid", -1, "Only accept connections from this UID")
	_ = cmd.MarkFlagRequired("socket")
	_ = cmd.MarkFlagRequired("allowed-uid")

	return cmd
}
