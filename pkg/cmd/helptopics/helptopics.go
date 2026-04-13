package helptopics

import "github.com/spf13/cobra"

// NewCmdYaml creates a help topic command for abox.yaml configuration reference.
func NewCmdYaml() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "yaml",
		Short: "abox.yaml configuration reference",
		Long:  yamlHelpText,
	}
	// Set Run to show Long text so command appears in its group (not "Additional help topics")
	cmd.Run = func(cmd *cobra.Command, args []string) {
		cmd.Println(cmd.Long)
	}
	return cmd
}

// NewCmdQuickstart creates a help topic command for the quick start guide.
func NewCmdQuickstart() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "quickstart",
		Short: "Quick start guide",
		Long:  quickstartHelpText,
	}
	// Set Run to show Long text so command appears in its group (not "Additional help topics")
	cmd.Run = func(cmd *cobra.Command, args []string) {
		cmd.Println(cmd.Long)
	}
	return cmd
}
