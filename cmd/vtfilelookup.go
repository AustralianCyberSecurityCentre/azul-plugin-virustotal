package cmd

import (
	"github.com/spf13/cobra"

	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/cmd/vtfilelookup"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:     "filelookup",
		Short:   "Lookup hashes from binary events in virustotal or an offline mirror.",
		Long:    ``,
		Example: ``,
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			vtfilelookup.Entrypoint()
		},
	})
}
