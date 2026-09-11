package cmd

import (
	"github.com/spf13/cobra"

	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/cmd/vtfilefeed"
)

var downloadFromBlob bool

func init() {
	cmd := &cobra.Command{
		Use:   "filefeed",
		Short: "Load VT metadata feed into Azul",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			vtfilefeed.Entrypoint(downloadFromBlob)
		},
	}

	cmd.Flags().BoolVar(
		&downloadFromBlob,
		"download-from-blob",
		false,
		"Download from Blob instead of Virustotal",
	)

	rootCmd.AddCommand(cmd)
}
