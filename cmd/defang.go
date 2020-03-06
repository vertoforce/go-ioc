package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/vertoforce/go-ioc/ioc"

	"github.com/spf13/cobra"
)

var defangCommand = &cobra.Command{
	Use:   "defang",
	Short: "Given stdin input, get the IOCs",

	Run: func(cmd *cobra.Command, args []string) {
		// Read all IOCs from stdin
		contents, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		iocs := ioc.GetIOCs(string(contents), getFangedIOCs, standardizeDefangs)
		printIOCHelper(iocs)
	},
}
