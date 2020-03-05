package ioc

import (
	"context"
	"fmt"
	"strings"
)

func ExampleGetIOCs() {
	data := `this is a bad url http[://]google[.]com/path`

	iocs := GetIOCs(data, false, true)
	fmt.Println(iocs)

	// Output: [google[.]com|Domain hxxp[://]google[.]com/path|URL]
}

func ExampleGetIOCsReader() {
	data := `this is a bad url http[://]google[.]com/path`

	iocs := GetIOCsReader(context.Background(), strings.NewReader(data), false, true)
	for ioc := range iocs {
		fmt.Println(ioc)
	}

	// Output: hxxp[://]google[.]com/path|URL
	// google[.]com|Domain
}

func ExampleIOC_Defang() {
	ioc := &IOC{IOC: "google.com", Type: Domain}
	ioc = ioc.Defang()
	fmt.Println(ioc)

	// Output: google[.]com|Domain
}
