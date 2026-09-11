package set

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/secretstore"
	"github.com/sandialabs/abox/internal/validation"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// Options holds the options for the set command.
type Options struct {
	Factory  *factory.Factory
	Name     string
	Key      string
	FromFile string
	FromEnv  string
	Stdin    bool
}

// NewCmdSet creates the `abox secrets set` command.
func NewCmdSet(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "set <instance> <key>",
		Short: "Store a secret value for an instance",
		Long: `Store a secret value under a key in the instance's host-side secret store.

The value is read from a file, an environment variable, or stdin — never a
command-line argument, which would leak it into shell history and the process
table. Prefer --from-file or --stdin; --from-env exposes the value in this
process's environment for the duration of the command.

Bind the stored key to a host+header in abox.yaml under http.secret_injections.`,
		Example: `  abox secrets set dev anthropic --from-file ./key.txt
  printf %s "$KEY" | abox secrets set dev anthropic --stdin
  abox secrets set dev anthropic --from-env ANTHROPIC_API_KEY`,
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completion.Sequence(completion.AllInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			opts.Key = args[1]
			if runF != nil {
				return runF(opts)
			}
			return runSet(opts)
		},
	}

	cmd.Flags().StringVar(&opts.FromFile, "from-file", "", "Read the secret value from this file")
	cmd.Flags().StringVar(&opts.FromEnv, "from-env", "", "Read the secret value from this environment variable")
	cmd.Flags().BoolVar(&opts.Stdin, "stdin", false, "Read the secret value from stdin")

	return cmd
}

func runSet(opts *Options) error {
	f := opts.Factory
	if !config.Exists(opts.Name) {
		return fmt.Errorf("instance %q does not exist", opts.Name)
	}
	if err := validation.ValidateSecretKey(opts.Key); err != nil {
		return err
	}

	value, err := readValue(opts)
	if err != nil {
		return err
	}

	paths, err := config.GetPaths(opts.Name)
	if err != nil {
		return err
	}
	if err := secretstore.New(paths.Secrets).Set(opts.Key, value); err != nil {
		return fmt.Errorf("failed to store secret: %w", err)
	}

	// Audit the key name only — never the value.
	logging.AuditInstance(opts.Name, logging.ActionSecretSet, "key", opts.Key)

	fmt.Fprintf(f.IO.Out, "Stored secret %q for instance %q.\n", opts.Key, opts.Name)
	fmt.Fprintf(f.IO.Out, "It takes effect the next time the HTTP filter starts (abox stop && abox start %s).\n", opts.Name)
	return nil
}

// readValue reads the secret value from exactly one of the configured sources.
func readValue(opts *Options) (string, error) {
	sources := 0
	if opts.FromFile != "" {
		sources++
	}
	if opts.FromEnv != "" {
		sources++
	}
	if opts.Stdin {
		sources++
	}
	if sources != 1 {
		return "", errors.New("provide exactly one of --from-file, --from-env, or --stdin")
	}

	switch {
	case opts.FromFile != "":
		b, err := os.ReadFile(opts.FromFile)
		if err != nil {
			return "", fmt.Errorf("failed to read secret file: %w", err)
		}
		return trimTrailingNewline(string(b)), nil
	case opts.FromEnv != "":
		v, ok := os.LookupEnv(opts.FromEnv)
		if !ok {
			return "", fmt.Errorf("environment variable %q is not set", opts.FromEnv)
		}
		return v, nil
	default: // --stdin
		b, err := io.ReadAll(opts.Factory.IO.In)
		if err != nil {
			return "", fmt.Errorf("failed to read secret from stdin: %w", err)
		}
		return trimTrailingNewline(string(b)), nil
	}
}

// trimTrailingNewline removes a single trailing newline (and optional CR) so a
// value piped via `echo` or read from a file doesn't carry an accidental newline.
func trimTrailingNewline(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	if len(s) > 0 && s[len(s)-1] == '\r' {
		s = s[:len(s)-1]
	}
	return s
}
