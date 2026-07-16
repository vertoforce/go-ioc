package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/vertoforce/go-ioc/ioc"
)

var stdinCommand = &cobra.Command{
	Use:   "stdin",
	Short: "Find IOCs from stdin",

	Run: func(cmd *cobra.Command, args []string) {
		stdin, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Println(err)
		}
		iocs := ioc.GetIOCs(string(stdin), getFangedIOCs)
		if standardizeDefangs {
			ioc.StandardizeDefangs(iocs)
		}
		printIOCHelper(iocs)
	},
}
