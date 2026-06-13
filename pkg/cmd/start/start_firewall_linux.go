//go:build linux

package start

import (
	"errors"
	"fmt"
	"io"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/firewall"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/pkg/cmd/factory"
)

// setupHostFirewall sets up iptables DNS redirect and configures UFW.
func setupHostFirewall(w io.Writer, f *factory.Factory, inst *config.Instance, name string) error {
	// Set up iptables DNS redirect — this is security-critical because without
	// the PREROUTING redirect, DNS queries bypass the dnsfilter entirely.
	if err := setupIptablesRedirect(w, f, inst); err != nil {
		return fmt.Errorf("failed to set up iptables DNS redirect: %w", err)
	}

	// Configure UFW if active
	if err := configureUFW(w, f, inst); err != nil {
		logging.Warn("failed to configure UFW", "error", err, "instance", name)
	}

	return nil
}

// configureUFW adds a UFW rule to allow traffic on the instance's bridge interface.
// This is only done if UFW is installed and active. Errors are non-fatal.
func configureUFW(w io.Writer, f *factory.Factory, inst *config.Instance) error {
	if f == nil {
		return nil
	}

	client, err := f.PrivilegeClientFor(inst.Name)
	if err != nil {
		return err
	}

	ufwClient := firewall.NewUFWClient(client)
	if !ufwClient.IsActive() {
		return nil
	}

	fmt.Fprintln(w, "Configuring UFW rules...")
	return ufwClient.Allow(inst.Bridge)
}

// setupIptablesRedirect adds iptables NAT rules to redirect DNS traffic (port 53)
// to the dnsfilter service. This is necessary because systemd-resolved always
// connects to port 53, so we use iptables PREROUTING to redirect to the actual
// dnsfilter port.
func setupIptablesRedirect(w io.Writer, f *factory.Factory, inst *config.Instance) error {
	if f == nil {
		return errors.New("factory not available")
	}

	client, err := f.PrivilegeClientFor(inst.Name)
	if err != nil {
		return fmt.Errorf("failed to get privilege client: %w", err)
	}

	fmt.Fprintln(w, "Setting up DNS redirect...")
	iptablesClient := firewall.NewIPTablesClient(client)
	return iptablesClient.AddDNSRedirect(inst)
}
