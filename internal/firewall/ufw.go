package firewall

import (
	"context"
	"fmt"
	"io"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/timeout"
)

// UFWClient wraps privilege RPC calls for UFW operations.
type UFWClient struct {
	priv rpc.PrivilegeClient
}

// NewUFWClient creates a new UFW client using the given privilege client.
func NewUFWClient(priv rpc.PrivilegeClient) *UFWClient {
	return &UFWClient{priv: priv}
}

// IsActive returns true if UFW is installed and active.
func (c *UFWClient) IsActive() bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel()

	resp, err := c.priv.UfwStatus(ctx, &rpc.Empty{})
	if err != nil {
		return false
	}
	return resp.Installed && resp.Active
}

// Allow adds a UFW rule to allow all traffic on the given bridge interface.
func (c *UFWClient) Allow(bridge string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel()

	_, err := c.priv.UfwAdd(ctx, &rpc.UfwReq{Bridge: bridge})
	return err
}

// Remove removes a UFW allow rule for the given bridge interface.
// This is idempotent - removing a non-existent rule does not return an error.
func (c *UFWClient) Remove(bridge string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel()

	_, err := c.priv.UfwRemove(ctx, &rpc.UfwReq{Bridge: bridge})
	return err
}

// Cleanup removes UFW rules for a bridge if UFW is active.
// The prefix is prepended to progress messages (use "" for no prefix, "  " for indented).
// Output is written to w; if w is nil, os.Stdout is used.
// Errors are logged as warnings but not returned.
func (c *UFWClient) Cleanup(w io.Writer, bridge, prefix string) {
	if !c.IsActive() {
		return
	}

	fmt.Fprintf(w, "%sRemoving UFW rules...\n", prefix)
	if err := c.Remove(bridge); err != nil {
		logging.Warn("failed to remove UFW rule", "error", err, "bridge", bridge)
	}
}
