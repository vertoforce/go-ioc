package cmd

import (
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/vertoforce/go-ioc/ioc"
)

var urlCommand = &cobra.Command{
	Use:   "url [URL]",
	Short: "Crawl a URL and print all the IOCs",
	Long:  "This command will only look for IOCs in the `text` of the page.  This means all the `href`s and other html tag data will not be included.",
	Args:  cobra.ExactArgs(1),

	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Println(err)
			return
		}
		req = req.WithContext(cmd.Context())
		iocs, err := ioc.GetIOCsFromURLPage(req)
		if err != nil {
			fmt.Println(err)
		}
		printIOCHelper(iocs)
	},
}
