package helptopics

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// commandGroup defines a group of commands for display.
type commandGroup struct {
	title    string
	commands []*cobra.Command
}

// NewCmdCommands creates a help topic command that auto-generates a command reference.
// It requires the root command to be passed in so it can introspect the command tree.
func NewCmdCommands(rootCmd *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "commands",
		Short: "Command reference",
		Long:  "Auto-generated command reference listing all abox commands.",
		Run: func(cmd *cobra.Command, args []string) {
			output := generateCommandReference(rootCmd)
			cmd.Println(output)
		},
	}
	return cmd
}

// generateCommandReference creates formatted help text from the command tree.
func generateCommandReference(rootCmd *cobra.Command) string {
	var sb strings.Builder

	sb.WriteString("Abox Command Reference\n")
	sb.WriteString("======================\n\n")

	// Collect commands by group
	groups := collectCommandGroups(rootCmd)

	// Format each group
	for _, group := range groups {
		if len(group.commands) == 0 {
			continue
		}

		sb.WriteString(strings.ToUpper(group.title))
		sb.WriteString("\n")

		// Calculate max width for alignment
		maxWidth := 0
		for _, cmd := range group.commands {
			usage := formatCommandUsage(cmd)
			if len(usage) > maxWidth {
				maxWidth = len(usage)
			}
		}

		// Print each command
		for _, cmd := range group.commands {
			usage := formatCommandUsage(cmd)
			padding := strings.Repeat(" ", maxWidth-len(usage)+2)
			fmt.Fprintf(&sb, "  %s%s%s\n", usage, padding, cmd.Short)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("GLOBAL FLAGS\n")
	sb.WriteString("      --log-level string    Log level (debug, info, warn, error)\n")
	sb.WriteString("      --log-format string   Log format (text, json)\n")
	sb.WriteString("      --log-file string     Write logs to file (in addition to stderr)\n")
	sb.WriteString("  -h, --help                Show help for any command\n")
	sb.WriteString("      --version             Show version information\n")
	sb.WriteString("\n")

	sb.WriteString("SEE ALSO\n")
	sb.WriteString("  abox <command> --help    Show detailed help for a command\n")
	sb.WriteString("  abox help yaml           abox.yaml configuration reference\n")
	sb.WriteString("  abox help environment    Environment variables reference\n")

	return sb.String()
}

// collectCommandGroups organizes commands by their GroupID.
func collectCommandGroups(rootCmd *cobra.Command) []commandGroup {
	// Define group order (matches root.go)
	groupOrder := []struct {
		id    string
		title string
	}{
		{"declarative", "Declarative Workflow"},
		{"lifecycle", "Instance Lifecycle"},
		{"security", "Security"},
		{"access", "Access"},
		{"files", "File Transfer"},
		{"management", "Instance Management"},
		{"utilities", "Utilities"},
		{"help", "Help Topics"},
	}

	// Build map of group ID to commands
	groupMap := make(map[string][]*cobra.Command)
	for _, cmd := range rootCmd.Commands() {
		if cmd.Hidden {
			continue
		}
		groupID := cmd.GroupID
		if groupID == "" {
			groupID = "other"
		}
		groupMap[groupID] = append(groupMap[groupID], cmd)
	}

	// Build result in desired order
	var result []commandGroup
	for _, g := range groupOrder {
		if cmds, ok := groupMap[g.id]; ok {
			result = append(result, commandGroup{
				title:    g.title,
				commands: cmds,
			})
			delete(groupMap, g.id)
		}
	}

	// Add any remaining groups
	for id, cmds := range groupMap {
		if id != "other" {
			result = append(result, commandGroup{
				title:    id,
				commands: cmds,
			})
		}
	}

	return result
}

// formatCommandUsage creates a usage string for a command.
func formatCommandUsage(cmd *cobra.Command) string {
	// For commands with subcommands, show just the command name
	if cmd.HasSubCommands() {
		return cmd.Name() + " <subcommand>"
	}

	// For leaf commands, show name with args
	use := cmd.Use
	// Extract just the first word (command name) and any args
	parts := strings.SplitN(use, " ", 2)
	if len(parts) == 2 {
		return parts[0] + " " + parts[1]
	}
	return use
}
