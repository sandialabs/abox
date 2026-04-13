// Package completion provides shell completion helpers for abox commands.
package completion

import (
	"context"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"

	"github.com/spf13/cobra"
)

// ArgCompleter completes a single positional argument.
type ArgCompleter func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective)

// Sequence returns a ValidArgsFunction that uses successive completers for each positional arg.
func Sequence(completers ...ArgCompleter) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) >= len(completers) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return completers[len(args)](cmd, args, toComplete)
	}
}

// Instances completes instance names, optionally filtered.
// Pass nil for no filtering (all instances).
func Instances(filter func(name string) bool) ArgCompleter {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		names, err := config.List()
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		if filter == nil {
			return names, cobra.ShellCompDirectiveNoFileComp
		}
		var filtered []string
		for _, name := range names {
			if filter(name) {
				filtered = append(filtered, name)
			}
		}
		return filtered, cobra.ShellCompDirectiveNoFileComp
	}
}

// Filter helpers
func isRunning(name string) bool {
	be, err := backend.ForInstance(&instanceRef{name})
	if err != nil {
		// Fall back to auto-detect
		be, err = backend.AutoDetect()
		if err != nil {
			return false
		}
	}
	return be.VM().IsRunning(name)
}

func isStopped(name string) bool {
	return !isRunning(name)
}

// instanceRef implements the interface needed by backend.ForInstance
type instanceRef struct {
	name string
}

func (i *instanceRef) GetBackend() string {
	inst, _, err := config.Load(i.name)
	if err != nil {
		return ""
	}
	return inst.Backend
}

// Convenience wrappers
func AllInstances() ArgCompleter     { return Instances(nil) }
func RunningInstances() ArgCompleter { return Instances(isRunning) }
func StoppedInstances() ArgCompleter { return Instances(isStopped) }

// Values completes from a fixed list of strings.
func Values(values ...string) ArgCompleter {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

// Repeat returns a ValidArgsFunction that uses the same completer for every positional arg.
func Repeat(completer ArgCompleter) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return completer(cmd, args, toComplete)
	}
}

// SnapshotsFor completes snapshot names for the instance specified at the given arg index.
func SnapshotsFor(instanceArgIndex int) ArgCompleter {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if instanceArgIndex >= len(args) {
			return nil, cobra.ShellCompDirectiveError
		}
		instanceName := args[instanceArgIndex]

		be, err := backend.ForInstance(&instanceRef{instanceName})
		if err != nil {
			// Fall back to auto-detect
			be, err = backend.AutoDetect()
			if err != nil {
				return nil, cobra.ShellCompDirectiveError
			}
		}

		sm := be.Snapshot()
		if sm == nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		ctx := context.Background()
		snapshots, err := sm.List(ctx, instanceName)
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		var names []string
		for _, s := range snapshots {
			names = append(names, s.Name)
		}
		return names, cobra.ShellCompDirectiveNoFileComp
	}
}
