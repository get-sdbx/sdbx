package cmd

import (
	"sort"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// CLIReferenceMetadata is an immutable documentation view of the Cobra
// command tree. Documentation generation uses this instead of maintaining a
// second handwritten command hierarchy.
type CLIReferenceMetadata struct {
	GlobalFlags []CLIReferenceFlag
	Commands    []CLIReferenceCommand
}

type CLIReferenceCommand struct {
	Path         string
	UseLine      string
	Short        string
	Runnable     bool
	SupportsJSON bool
	Flags        []CLIReferenceFlag
}

type CLIReferenceFlag struct {
	Name       string
	Shorthand  string
	Type       string
	Default    string
	Usage      string
	Deprecated string
	Hidden     bool
}

// DocumentationCLIReference returns the complete current command and flag
// surface, including Cobra's built-in help and completion commands.
func DocumentationCLIReference() CLIReferenceMetadata {
	rootCmd.InitDefaultHelpCmd()
	rootCmd.InitDefaultCompletionCmd()
	rootCmd.InitDefaultHelpFlag()

	reference := CLIReferenceMetadata{
		GlobalFlags: documentationFlags(rootCmd.PersistentFlags()),
	}
	var visit func(*cobra.Command)
	visit = func(command *cobra.Command) {
		command.InitDefaultHelpFlag()
		reference.Commands = append(reference.Commands, CLIReferenceCommand{
			Path:         command.CommandPath(),
			UseLine:      command.UseLine(),
			Short:        command.Short,
			Runnable:     command.Runnable(),
			SupportsJSON: supportsJSON(command),
			Flags:        documentationFlags(command.NonInheritedFlags()),
		})
		for _, child := range command.Commands() {
			visit(child)
		}
	}
	visit(rootCmd)
	sort.Slice(reference.Commands, func(i, j int) bool {
		return reference.Commands[i].Path < reference.Commands[j].Path
	})
	return reference
}

func documentationFlags(flags *pflag.FlagSet) []CLIReferenceFlag {
	if flags == nil {
		return nil
	}
	result := make([]CLIReferenceFlag, 0, flags.NFlag())
	flags.VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		result = append(result, CLIReferenceFlag{
			Name:       flag.Name,
			Shorthand:  flag.Shorthand,
			Type:       flag.Value.Type(),
			Default:    flag.DefValue,
			Usage:      flag.Usage,
			Deprecated: flag.Deprecated,
			Hidden:     flag.Hidden,
		})
	})
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result
}
