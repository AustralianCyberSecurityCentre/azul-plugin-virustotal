package cmd

import (
	"github.com/spf13/cobra"

	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/cmd/vthuntfeed"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:     "huntfeed",
		Short:   "Use periodically to poll for latest livehunt notifications and trigger download of hits.",
		Long:    ``,
		Example: ``,
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			vthuntfeed.Entrypoint()
		},
	})
}
