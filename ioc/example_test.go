package ioc

import (
	"context"
	"fmt"
	"strings"
)

func ExampleGetIOCs() {
	data := `this is a bad url http[://]google[.]com/path`

	iocs := GetIOCs(data, false)
	iocs = SortByType(iocs)
	StandardizeDefangs(iocs)
	fmt.Println(iocs)

	// Output: [google[.]com|Domain hxxp[://]google[.]com/path|URL]
}

func ExampleGetIOCsReader() {
	reader := strings.NewReader(`this is a bad url http[://]google[.]com/path`)

	iocs := make(chan *IOC)
	go func() {
		defer close(iocs)
		err := GetIOCsReader(context.Background(), reader, false, iocs)
		if err != nil {
			panic(err)
		}
	}()
	for ioc := range iocs {
		// Print IOC
		fmt.Println(ioc)
	}
}

func ExampleIOC_Defang() {
	ioc := &IOC{IOC: "google.com", Type: Domain}
	ioc = ioc.Defang()
	fmt.Println(ioc)
	ioc = ioc.Fang()
	fmt.Println(ioc)

	// Output: google[.]com|Domain
	// google.com|Domain
}
