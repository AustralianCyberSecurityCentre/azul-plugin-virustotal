package cmd

import (
	"github.com/spf13/cobra"

	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/cmd/vtfilefeed"
)

var downloadFromVT bool

func init() {
	cmd := &cobra.Command{
		Use:   "filefeed-download",
		Short: "Load VT metadata feed into Azul",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			vtfilefeed.Entrypoint(downloadFromVT)
		},
	}

	cmd.Flags().BoolVar(
		&downloadFromVT,
		"download-from-vt",
		false,
		"Download from VirusTotal instead of Blob Storage",
	)

	rootCmd.AddCommand(cmd)
}
