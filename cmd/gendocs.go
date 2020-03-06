package cmd

import (
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/spf13/cobra/doc"
)

var gendocsCommand = &cobra.Command{
	Use:   "docs",
	Short: "Generate docs",

	Run: func(cmd *cobra.Command, args []string) {
		os.Mkdir("docs", os.ModePerm)
		err := doc.GenMarkdownTree(rootCmd, "./docs")
		if err != nil {
			log.Fatal(err)
		}
	},
}
