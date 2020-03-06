package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	"github.com/vertoforce/go-ioc/ioc"
)

var stdinCommand = &cobra.Command{
	Use:   "stdin",
	Short: "Analyze stdin",

	Run: func(cmd *cobra.Command, args []string) {
		stdin, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			fmt.Println(err)
		}
		iocs := ioc.GetIOCs(string(stdin), getFangedIOCs, standardizeDefangs)
		printIOCHelper(iocs)
	},
}
