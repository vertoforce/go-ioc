package ioc

import (
	"regexp"
	"strings"
)

// Defang Structures to defang using our standardized defanging
type defangMap map[Type][]defangPair
type defangPair struct {
	defanged string
	fanged   string
}

// Our standardized defangs use all square brackets []
var defangReplacements = defangMap{
	Email: {
		{"[AT]", "@"},
		{"[.]", "."},
	},
	Domain: {
		{"[.]", "."},
	},
	IPv4: {
		{"[.]", "."},
	},
	IPv6: {
		{"[:]", ":"},
	},
	URL: {
		{"hxxp", "http"},
		{"[://]", "://"},
		{"[.]", "."},
	},
}

// Defang Takes an IOC and defangs it using the standard defrangReplacements
func (ioc *IOC) Defang() *IOC {
	copy := *ioc
	ioc = &copy

	// Just do a string replace on each
	if replacements, ok := defangReplacements[ioc.Type]; ok {
		for _, fangPair := range replacements {
			ioc.IOC = strings.ReplaceAll(ioc.IOC, fangPair.fanged, fangPair.defanged)
		}
	}

	return ioc
}

// Fang Structures to fang using all possible defangs
type regexReplacement struct {
	pattern *regexp.Regexp
	replace string
}

var dotReplace = regexReplacement{regexp.MustCompile(`\ *[([]?\ *((dot)|\.)\ *[])]?\ *`), "."}
var fangReplacements = map[Type][]regexReplacement{
	Email: {
		{regexp.MustCompile(`(\ ?[([]?\ ?(([aA][tT])|@)\ ?[])]?\ ?)`), "@"},
		dotReplace,
	},
	Domain: {
		dotReplace,
	},
	IPv4: {
		dotReplace,
	},
	IPv6: {
		{regexp.MustCompile(`[([]:[])]`), "."},
	},
	URL: {
		{regexp.MustCompile(`hxxp`), "http"},
		{regexp.MustCompile(`[[(]://[)]]`), "://"},
		dotReplace,
	},
}

// Fang Takes an IOC and removes the defanging stuff from it
func (ioc *IOC) Fang() *IOC {
	copy := *ioc
	ioc = &copy

	// String replace all defangs in our standard set
	if replacements, ok := defangReplacements[ioc.Type]; ok {
		for _, fangPair := range replacements {
			ioc.IOC = strings.ReplaceAll(ioc.IOC, fangPair.defanged, fangPair.fanged)
		}
	}

	// Regex replace everything from the fang replacements
	if replacements, ok := fangReplacements[ioc.Type]; ok {
		for _, regexReplacement := range replacements {
			// Offset is incase we shrink the string and need to offset locations
			offset := 0

			// Get indexes of replacements and replace them
			toReplace := regexReplacement.pattern.FindAllStringIndex(ioc.IOC, -1)
			for _, location := range toReplace {
				// Update this found string
				startSize := len(ioc.IOC)
				ioc.IOC = ioc.IOC[0:location[0]-offset] + regexReplacement.replace + ioc.IOC[location[1]-offset:len(ioc.IOC)]
				// Update offset with how much the string shrunk (or grew)
				offset += startSize - len(ioc.IOC)
			}
		}
	}

	return ioc
}

// IsFanged Takes an IOC and returns if it is fanged.  Non fanging types (bitcoin, hashes, file, cve) are always determined to not be fanged
func (ioc *IOC) IsFanged() bool {
	if ioc.Type == Bitcoin ||
		ioc.Type == MD5 ||
		ioc.Type == SHA1 ||
		ioc.Type == SHA256 ||
		ioc.Type == SHA512 ||
		ioc.Type == File ||
		ioc.Type == CVE {
		return false
	}

	// Basically just check if the fanged version is different from the input
	// This does label a partially fanged IOC is NOT fanged.  I.e https://exampe[.]test.com/url is labled as NOT fanged
	if ioc.Fang().IOC == ioc.IOC {
		// They are equal, it's fanged
		return true
	}
	return false
}
