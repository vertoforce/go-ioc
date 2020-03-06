package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vertoforce/go-ioc/ioc"
)

var rssCommand = &cobra.Command{
	Use:   "rss [RSS URL]",
	Short: "Crawl a RSS feed and get all IOCs from articles in the feed",
	Args:  cobra.ExactArgs(1),

	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]
		iocs, err := ioc.GetIOCsFromRSS(context.Background(), url)
		if err != nil {
			fmt.Println(err)
		}
		printIOCHelper(iocs)
	},
}
