package ioc

import (
	"bytes"
	"fmt"
	"sort"
	"text/tabwriter"
)

// IOC Struct to store an IOC and it's type
type IOC struct {
	IOC  string
	Type Type // hash, url, domain, file
}

// String Takes an IOC and prints in csv form: IOC|Type
func (ioc *IOC) String() string {
	return ioc.IOC + "|" + ioc.Type.String()
}

// Type Type of IOC (bitcoin, sha1, etc)
type Type int

// Types ordered in list of largest to smallest (so an email is > domain since an email contains a domain)
//go:generate stringer -type=Type
const (
	Unknown Type = iota
	Bitcoin
	MD5
	SHA1
	SHA256
	SHA512
	Domain
	Email
	IPv4
	IPv6
	URL
	File
	CVE
	CAPEC
	CWE
	CPE
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
	CAPEC,
	CWE,
	CPE,
}

// -- []IOC helpers --

// SortByType takes a group of IOCs and sorts them by their type
func SortByType(iocs []*IOC) []*IOC {
	copy := iocs
	sort.Slice(copy, func(i, j int) bool {
		return iocs[i].Type < iocs[j].Type
	})
	return copy
}

// PrintIOCs Takes IOCs and prints them according to the format desired
// Format can be csv or table
func PrintIOCs(iocs []*IOC, format string) string {
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
func PrintIOCsCSV(iocs []*IOC) string {
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
func PrintIOCsTable(iocs []*IOC) string {
	w := new(tabwriter.Writer)

	ret := new(bytes.Buffer)
	w.Init(ret, 0, 8, 1, ' ', 0)

	// Loop through and set table
	var lastType Type
	lastType = -1
	for _, ioc := range iocs {
		if ioc.Type != lastType {
			fmt.Fprintln(w, "# "+ioc.Type.String())
			lastType = ioc.Type
		}
		fmt.Fprintln(w, ioc.IOC+"\t"+ioc.Type.String())
	}

	w.Flush()
	return ret.String()
}

// PrintIOCsStats Given iocs print the stats associated with them
func PrintIOCsStats(iocs []*IOC) string {
	stats := GetIOCsCounts(iocs)

	ret := ""
	for iocType, count := range stats {
		ret += fmt.Sprintf("%s: %d\n", iocType.String(), count)
	}

	return ret
}

// GetIOCsCounts Given []IOC return count of each
func GetIOCsCounts(iocs []*IOC) map[Type]int {
	stats := make(map[Type]int)

	for _, ioc := range iocs {
		if _, ok := stats[ioc.Type]; ok {
			stats[ioc.Type]++
		} else {
			stats[ioc.Type] = 1
		}
	}

	return stats
}
