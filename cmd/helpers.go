package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/vertoforce/go-ioc/ioc"
)

// printIOCHelper Helper to manage printing with provided flags
func printIOCHelper(iocs []*ioc.IOC) {
	if iocSort {
		iocs = ioc.SortByType(iocs)
	}

	if printFanged {
		for i := range iocs {
			iocs[i] = iocs[i].Fang()
		}
	}

	if iocPrintStats {
		fmt.Println("Stats:")
		fmt.Println(ioc.PrintIOCsStats(iocs))
	}

	// Write to file if specified
	if outputFile != "" {
		ioutil.WriteFile(outputFile, []byte(ioc.PrintIOCs(iocs, iocPrintFormat)), os.ModePerm)
	} else {
		fmt.Println(ioc.PrintIOCs(iocs, iocPrintFormat))
	}

}
