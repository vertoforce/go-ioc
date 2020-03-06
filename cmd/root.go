package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var iocPrintFormat string
var outputFile string
var iocTypes string

var iocPrintStats bool
var iocSort bool

var standardizeDefangs bool
var printFanged bool
var getFangedIOCs bool

var rootCmd = &cobra.Command{
	Use:     "go-ioc [command]",
	Short:   "go-ioc is a tool to extract IOCs from various sources",
	Long:    "go-ioc can be used to extract IOCs from articles, RSS feeds, and text.",
	Example: "go-ioc url https://google.com",

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("No command.")
	},
}

// Execute execute command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Commands
	rootCmd.AddCommand(urlCommand)
	rootCmd.AddCommand(rssCommand)
	rootCmd.AddCommand(gendocsCommand)
	rootCmd.AddCommand(stdinCommand)

	// Root flags
	rootCmd.PersistentFlags().StringVarP(&iocPrintFormat, "format", "f", "csv", "Print format for printing IOCs.  Options include: csv, table")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Save IOCs to file")
	rootCmd.PersistentFlags().BoolVar(&iocPrintStats, "stats", false, "Print count of each IOC found at start of output")
	rootCmd.PersistentFlags().BoolVarP(&iocSort, "sort", "s", true, "Sort IOCs by their type")
	rootCmd.PersistentFlags().BoolVar(&standardizeDefangs, "standardizeDefangs", true, "Standardize all defanged IOCs using square brackets")
	rootCmd.PersistentFlags().BoolVar(&printFanged, "printFanged", false, "Print all IOCs fanged, will override standardizeDefangs")
	rootCmd.PersistentFlags().BoolVar(&getFangedIOCs, "all", false, "Get all fanged IOCs.  This typically is rather noisy in that it finds _all_ links, etc")
}
