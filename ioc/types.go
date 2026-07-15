package ioc

import (
	"bytes"
	"encoding/json"
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
//
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
	// Appended after CPE so existing enum values do not shift.
	MITRE
	MAC
	Monero
	Ethereum
	SSDeep
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
	MITRE,
	MAC,
	Monero,
	Ethereum,
	SSDeep,
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
// Format can be csv, table, or json
func PrintIOCs(iocs []*IOC, format string) string {
	switch format {
	case "csv":
		return PrintIOCsCSV(iocs)
	case "table":
		return PrintIOCsTable(iocs)
	case "json":
		return PrintIOCsJSON(iocs)
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

// PrintIOCsJSON Takes []IOC and returns them as a JSON array of {ioc,type} objects
func PrintIOCsJSON(iocs []*IOC) string {
	type jsonIOC struct {
		IOC  string `json:"ioc"`
		Type string `json:"type"`
	}
	out := make([]jsonIOC, 0, len(iocs))
	for _, ioc := range iocs {
		out = append(out, jsonIOC{IOC: ioc.IOC, Type: ioc.Type.String()})
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
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
		stats[ioc.Type] = stats[ioc.Type] + 1
	}

	return stats
}
