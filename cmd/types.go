package cmd

import (
	"fmt"

	"github.com/vertoforce/go-ioc/ioc"

	"github.com/spf13/cobra"
)

var typesCommand = &cobra.Command{
	Use:   "printtypes",
	Short: "Print all available types",

	Run: func(cmd *cobra.Command, args []string) {
		for _, Type := range ioc.Types {
			fmt.Println(Type)
		}
	},
}
