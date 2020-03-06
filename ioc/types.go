package ioc

import (
	"bytes"
	"fmt"
	"sort"
	"text/tabwriter"
)

// IOC Indicator of compromise
type IOC string

func (ioc IOC) Type() Type {
	for _, Type := range Types {
		if iocRegexes[Type].MatchString(string(ioc)) {
			return Type
		}
	}
	return Unknown
}

// String Takes an IOC and prints in csv form: IOC|Type
func (ioc IOC) String() string {
	return fmt.Sprintf("%s|%s", ioc, ioc.Type())
}

// Type Type of IOC (bitcoin, sha1, etc)
type Type string

// Types
const (
	Unknown Type = "Unknown"
	Bitcoin      = "Bitcoin"
	MD5          = "MD5"
	SHA1         = "SHA1"
	SHA256       = "SHA256"
	SHA512       = "SHA512"
	Domain       = "Domain"
	Email        = "Email"
	IPv4         = "IPv4"
	IPv6         = "IPv6"
	URL          = "URL"
	File         = "File"
	CVE          = "CVE"
)

// Types of all IOCs
var Types = []Type{
	Bitcoin,
	MD5,
	SHA1,
	SHA256,
	SHA512,
	Domain,
	Email,
	IPv4,
	IPv6,
	URL,
	File,
	CVE,
}

// -- []IOC helpers --

// SortByType takes a group of IOCs and sorts them by their type
func SortByType(iocs []*IOC) []*IOC {
	copy := iocs
	sort.Slice(copy, func(i, j int) bool {
		return iocs[i].Type() < iocs[j].Type()
	})
	return copy
}

// PrintIOCs Takes IOCs and prints them according to the format desired
// Format can be csv or table
func PrintIOCs(iocs []IOC, format string) string {
	switch format {
	case "csv":
		return PrintIOCsCSV(iocs)
	case "table":
		return PrintIOCsTable(iocs)
	default:
		return PrintIOCsCSV(iocs)
	}
}

// PrintIOCsCSV Takes []IOC and returns them in a csv format
func PrintIOCsCSV(iocs []IOC) string {
	ret := ""

	for i, ioc := range iocs {
		ret += ioc.String()
		if i < len(iocs)-1 {
			ret += "\n"
		}
	}

	return ret
}

// PrintIOCsTable Takes []IOC and returns them in a csv format
func PrintIOCsTable(iocs []IOC) string {
	w := new(tabwriter.Writer)

	ret := new(bytes.Buffer)
	w.Init(ret, 0, 8, 1, ' ', 0)

	// Loop through and set table
	var lastType Type
	lastType = ""
	for _, ioc := range iocs {
		if ioc.Type() != lastType {
			fmt.Fprintln(w, "# "+ioc.Type())
			lastType = ioc.Type()
		}
		fmt.Fprintf(w, "%s\t%s", ioc, ioc.Type())
	}

	w.Flush()
	return ret.String()
}

// PrintIOCsStats Given iocs print the stats associated with them
func PrintIOCsStats(iocs []IOC) string {
	stats := GetIOCsCounts(iocs)

	ret := ""
	for iocType, count := range stats {
		ret += fmt.Sprintf("%s: %d\n", iocType, count)
	}

	return ret
}

// GetIOCsCounts Given []IOC return count of each
func GetIOCsCounts(iocs []IOC) map[Type]int {
	stats := make(map[Type]int)

	for _, ioc := range iocs {
		if _, ok := stats[ioc.Type()]; ok {
			stats[ioc.Type()]++
		} else {
			stats[ioc.Type()] = 1
		}
	}

	return stats
}
