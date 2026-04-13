package tap

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/errhint"
	"github.com/sandialabs/abox/internal/httpfilter"
	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/privilege"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// Options holds the options for the tap command.
type Options struct {
	Factory    *factory.Factory
	Name       string
	Output     string // -o: write PCAP to file
	Count      int    // -c: packet count limit
	Filter     string // -f: BPF filter expression
	SnapLen    int    // -s: snapshot length
	IncludeSSH bool   // --include-ssh: include SSH management traffic
}

// NewCmdTap creates a new tap command.
func NewCmdTap(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "tap <instance> [flags] [-- tcpdump-flags...]",
		Short: "Capture traffic from an instance with TLS decryption",
		Long: `Capture network traffic on an instance's bridge interface using tcpdump.

Because the instance's HTTP proxy performs TLS interception (MITM), this
command also exports the TLS session keys so that tools like Wireshark and
Suricata can decrypt HTTPS traffic in the capture. The key file is written
to the instance's logs directory (logs/keys.log).

DNS traffic is unencrypted on the bridge and is visible without the key
file. HTTPS decryption requires MITM to be enabled (the default).

By default, SSH management traffic between the host and VM (used by
"abox ssh") is excluded from the capture. Use --include-ssh to include it.

When stdout is a terminal, tcpdump shows decoded packets interactively.
When stdout is piped, raw PCAP binary is written for tool consumption.

Requires tcpdump to be installed (sudo apt install tcpdump). On most
Linux distributions, tcpdump has the necessary capture permissions by
default. If not, see the error message for remediation steps.`,
		Example: `  abox tap dev                                 # Interactive decoded output
  abox tap dev -o capture.pcap                 # Write PCAP to file
  abox tap dev | wireshark -k -i -             # Pipe to Wireshark
  abox tap dev --filter "tcp port 443"         # Only HTTPS traffic
  abox tap dev --filter "udp port 53"          # Only DNS traffic
  abox tap dev -c 100                          # Stop after 100 packets
  abox tap dev --include-ssh                   # Include SSH management traffic
  abox tap dev -- -v -X                        # Pass extra tcpdump flags

  # Decrypt HTTPS in a saved capture:
  tshark -o tls.keylog_file:~/.local/share/abox/instances/dev/logs/keys.log \
    -r capture.pcap -Y http`,
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: completion.Sequence(completion.RunningInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if runF != nil {
				return runF(opts)
			}
			// Collect extra args after --
			var extraArgs []string
			if cmd.ArgsLenAtDash() >= 0 {
				extraArgs = args[cmd.ArgsLenAtDash():]
			}
			return runTap(opts, extraArgs)
		},
	}

	cmd.Flags().StringVarP(&opts.Output, "output", "o", "", "Write PCAP to file instead of stdout")
	cmd.Flags().IntVarP(&opts.Count, "count", "c", 0, "Exit after capturing N packets")
	cmd.Flags().StringVarP(&opts.Filter, "filter", "f", "", "BPF filter expression")
	cmd.Flags().IntVarP(&opts.SnapLen, "snap-len", "s", 0, "Snapshot length per packet (bytes)")
	cmd.Flags().BoolVar(&opts.IncludeSSH, "include-ssh", false, "Include SSH management traffic in capture")

	return cmd
}

func runTap(opts *Options, extraArgs []string) error {
	f := opts.Factory
	name := opts.Name

	// Warn if running under sudo — path resolution breaks because
	// os.UserHomeDir() returns /root instead of the invoking user's home.
	if os.Getuid() == 0 && os.Getenv("SUDO_USER") != "" {
		return &errhint.ErrHint{
			Err:  errors.New("abox should not be run with sudo"),
			Hint: "Run without sudo: abox tap " + name + "\ntcpdump privileges are escalated automatically when needed.",
		}
	}

	// Verify instance is running
	be, err := f.BackendFor(name)
	if err != nil {
		return fmt.Errorf("failed to get backend: %w", err)
	}

	inst, paths, err := instance.LoadRunning(name, be.VM())
	if err != nil {
		return err
	}

	// Find tcpdump
	tcpdumpBin, err := exec.LookPath("tcpdump")
	if err != nil {
		return &errhint.ErrHint{
			Err:  errors.New("tcpdump not found"),
			Hint: "Install tcpdump: sudo apt install tcpdump",
		}
	}

	// Connect to httpfilter and start TLS key logging
	client, err := httpfilter.Dial(paths.HTTPSocket)
	if err != nil {
		return fmt.Errorf("failed to connect to HTTP filter: %w\nIs the instance fully started?", err)
	}
	defer func() { _ = client.Close() }()

	if err := startKeyLogging(client, paths.KeyLog); err != nil {
		return err
	}

	// Ensure we stop key logging on exit
	defer func() {
		stopCtx, stopCancel := httpfilter.ClientContext()
		defer stopCancel()
		_ = client.StopKeyLog(stopCtx)
	}()

	// Build tcpdump arguments
	args := buildTcpdumpArgs(opts, f, inst, extraArgs)

	printCaptureInfo(opts, inst, paths)

	logging.AuditInstance(name, logging.ActionTap, "bridge", inst.Bridge)

	return runTcpdump(tcpdumpBin, args, opts, paths)
}

// startKeyLogging connects to httpfilter and starts TLS key logging.
func startKeyLogging(client *httpfilter.Client, keyLogPath string) error {
	ctx, cancel := httpfilter.ClientContext()
	defer cancel()

	if err := client.StartKeyLog(ctx, keyLogPath); err != nil {
		return fmt.Errorf("failed to start TLS key logging: %w", err)
	}
	return nil
}

// buildTcpdumpArgs constructs the tcpdump command-line arguments.
func buildTcpdumpArgs(opts *Options, f *factory.Factory, inst *config.Instance, extraArgs []string) []string {
	args := []string{"-i", inst.Bridge, "-n"}

	if opts.Output != "" {
		args = append(args, "-w", opts.Output)
	} else if !f.IO.IsTerminal() {
		// Pipe mode: output raw PCAP on stdout
		args = append(args, "-w", "-")
	}

	if opts.Count > 0 {
		args = append(args, "-c", strconv.Itoa(opts.Count))
	}

	if opts.SnapLen > 0 {
		args = append(args, "-s", strconv.Itoa(opts.SnapLen))
	}

	// Extra flags from after --
	args = append(args, extraArgs...)

	// BPF filter must be last
	if filter := buildBPFFilter(opts.Filter, inst.Gateway, opts.IncludeSSH); filter != "" {
		args = append(args, filter)
	}

	return args
}

// printCaptureInfo prints capture information to stderr.
func printCaptureInfo(opts *Options, inst *config.Instance, paths *config.Paths) {
	fmt.Fprintf(os.Stderr, "Capturing on bridge %s (Ctrl+C to stop)\n", inst.Bridge)
	fmt.Fprintf(os.Stderr, "TLS key log: %s\n", paths.KeyLog)
	if opts.Output != "" {
		fmt.Fprintf(os.Stderr, "PCAP output: %s\n", opts.Output)
	}
	if !opts.IncludeSSH && inst.Gateway != "" {
		fmt.Fprintf(os.Stderr, "Excluding SSH traffic from %s (use --include-ssh to include)\n", inst.Gateway)
	}
	fmt.Fprintf(os.Stderr, "\n")
}

// runTcpdump starts tcpdump (escalating privileges if needed), forwards signals, and
// handles the exit status.
func runTcpdump(tcpdumpBin string, args []string, opts *Options, paths *config.Paths) error {
	var cmd *exec.Cmd
	escalated := needsEscalation(tcpdumpBin)
	if escalated {
		tool, err := privilege.SelectEscalationTool()
		if err != nil {
			return &errhint.ErrHint{
				Err:  errors.New("tcpdump requires capture privileges"),
				Hint: "Grant tcpdump capabilities:\n  sudo setcap cap_net_raw,cap_net_admin=eip " + tcpdumpBin,
			}
		}
		cmd = exec.Command(tool, append([]string{tcpdumpBin}, args...)...)
	} else {
		cmd = exec.Command(tcpdumpBin, args...)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start tcpdump: %w", err)
	}

	// Forward signals to tcpdump so it can print stats before exiting.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		signal.Stop(sigCh)
		_ = cmd.Process.Signal(sig)
	}()

	err := cmd.Wait()
	signal.Stop(sigCh)

	// Print decryption hint after capture
	if opts.Output != "" {
		fmt.Fprintf(os.Stderr, "\nDecrypt with:\n")
		fmt.Fprintf(os.Stderr, "  wireshark -o tls.keylog_file:%s -r %s\n", paths.KeyLog, opts.Output)
		fmt.Fprintf(os.Stderr, "  tshark -o tls.keylog_file:%s -r %s -Y http\n", paths.KeyLog, opts.Output)
	}

	return handleTcpdumpExit(err, escalated, tcpdumpBin)
}

// handleTcpdumpExit interprets the tcpdump exit status and returns an appropriate error.
func handleTcpdumpExit(err error, escalated bool, tcpdumpBin string) error {
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		// Only suggest privilege remediation if we didn't already escalate.
		// After escalation, exit code 1 is likely a filter or interface error.
		if escalated {
			return errors.New("tcpdump failed (exit code 1); check the interface name and BPF filter syntax")
		}
		return &errhint.ErrHint{
			Err:  errors.New("tcpdump failed (exit code 1)"),
			Hint: hintForTcpdumpError(tcpdumpBin),
		}
	}
	return fmt.Errorf("tcpdump exited: %w", err)
}

// hintForTcpdumpError returns a remediation hint for common tcpdump failures.
func hintForTcpdumpError(tcpdumpBin string) string {
	var hints []string
	hints = append(hints, "This may be a permission issue. Try:")
	hints = append(hints, "  sudo setcap cap_net_raw,cap_net_admin=eip "+tcpdumpBin)
	hints = append(hints, "If using a BPF filter, check the filter syntax.")
	return strings.Join(hints, "\n")
}

// buildBPFFilter constructs the effective BPF filter expression.
// By default, SSH management traffic (host <-> gateway on port 22) is excluded
// to reduce noise from abox ssh sessions. The exclusion is skipped when
// includeSSH is true or when gateway is empty.
func buildBPFFilter(userFilter, gateway string, includeSSH bool) string {
	var parts []string

	if !includeSSH && gateway != "" {
		parts = append(parts, fmt.Sprintf("not (tcp port 22 and host %s)", gateway))
	}

	if userFilter != "" {
		parts = append(parts, fmt.Sprintf("(%s)", userFilter))
	}

	return strings.Join(parts, " and ")
}

// needsEscalation checks whether tcpdump needs privilege escalation to capture.
func needsEscalation(tcpdumpBin string) bool {
	if os.Getuid() == 0 {
		return false
	}
	out, err := exec.Command("getcap", tcpdumpBin).Output()
	if err != nil {
		return true
	}
	s := string(out)
	return !strings.Contains(s, "cap_net_raw") || !strings.Contains(s, "cap_net_admin")
}
