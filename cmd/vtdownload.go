package cmd

import (
	"github.com/spf13/cobra"

	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/cmd/vtdownload"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:     "download",
		Short:   "Handles requests for downloading binaries from VirusTotal.",
		Long:    ``,
		Example: ``,
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			vtdownload.Entrypoint()
		},
	})
}
