package cmd

import (
	"github.com/spf13/cobra"

	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/cmd/vtfilefeed"
)

func init() {
	cmd := cobra.Command{
		Use:     "filefeed",
		Short:   "Load vt metadata feed into Azul.",
		Long:    ``,
		Example: ``,
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			vtfilefeed.Entrypoint()
		},
	}
	cmd.Flags().String()
	rootCmd.AddCommand(&)
}
