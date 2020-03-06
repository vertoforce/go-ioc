package ioc

import (
	"context"
	"io"
	"io/ioutil"

	"github.com/vertoforce/multiregex"
)

const (
	maxHTMLRecursionDepth = 100
)

// GetIOCs Return a slice of IOCs from the provided data
func GetIOCs(data string, getFangedIOCs bool, standardizeDefangs bool) []IOC {
	var iocs []IOC

	// Loop through the types to find and search the provided data
	for _, Type := range Types {
		matches := UniqueStringSlice(iocRegexes[Type].FindAllString(data, -1))
		for _, match := range matches {
			ioc := IOC(match)

			// Only add if defanged or we are getting all fanged IOCs
			if !ioc.IsFanged() || getFangedIOCs {
				// Standardize Defangs
				if standardizeDefangs {
					ioc = ioc.Fang().Defang()
				}

				iocs = append(iocs, ioc)
			}
		}
	}

	return iocs
}

// GetIOCsReader Get iocs from reader
// TODO: This is not deterministic output
func GetIOCsReader(ctx context.Context, reader io.Reader, getFangedIOCs bool, standardizeDefangs bool) chan IOC {
	// Combine all rules in to a RuleSet
	ruleSet := multiregex.RuleSet{}
	for _, rule := range iocRegexes {
		ruleSet = append(ruleSet, rule)
	}

	matches := make(chan IOC)

	ctxMatching, cancelMatching := context.WithCancel(ctx)
	// TODO: Add support for maxMatchLengths
	matchesRaw := ruleSet.GetMatchedDataReader(ctxMatching, ioutil.NopCloser(reader), nil)

	go func() {
		defer cancelMatching()
		defer close(matches)

		for match := range matchesRaw {
			ioc := IOC(string(match.Data))

			// Only add if defanged or we are getting all fanged IOCs
			if !ioc.IsFanged() || getFangedIOCs {
				// Standardize Defangs
				if standardizeDefangs {
					ioc = ioc.Fang().Defang()
				}

				select {
				case matches <- ioc:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return matches
}
