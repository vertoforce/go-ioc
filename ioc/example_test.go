package ioc

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

func ExampleGetIOCs() {
	data := `this is a bad url http[://]google[.]com/path`

	iocs := GetIOCs(data, false, true)
	sort.SliceStable(iocs, func(i, j int) bool {
		elements := []string{iocs[i].Type.String(), iocs[j].Type.String()}
		slice := sort.StringSlice(elements)
		sort.Sort(slice)
		return slice[0] == iocs[i].Type.String()
	})
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
	ioc = ioc.Fang()
	fmt.Println(ioc)

	// Output: google[.]com|Domain
	// google.com|Domain
}
