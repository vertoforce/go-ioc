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

// ParseIOC Parses a single IOC and gets its type.
// It will only return the highest IOC type (so if it's an email, it will return the email, not the domain in the email)
func ParseIOC(ioc string) *IOC {
	iocs := GetIOCs(ioc, true, false)
	ret := &IOC{}
	for _, ioc := range iocs {
		// Only return the "highest" IOC
		if ioc.Type > ret.Type {
			ret = ioc
		}
	}

	return ret
}

// GetIOCs Return a slice of IOCs from the provided data
func GetIOCs(data string, getFangedIOCs bool, standardizeDefangs bool) []*IOC {
	var iocs []*IOC

	// Loop through the types to find and search the provided data
	for iocType, regex := range iocRegexes {
		matches := uniqueStringSlice(regex.FindAllString(data, -1))
		for _, match := range matches {
			ioc := &IOC{IOC: match, Type: iocType}

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
func GetIOCsReader(ctx context.Context, reader io.Reader, getFangedIOCs bool, standardizeDefangs bool) chan *IOC {
	// Combine all rules in to a RuleSet
	ruleSet := multiregex.RuleSet{}
	for _, rule := range iocRegexes {
		ruleSet = append(ruleSet, rule)
	}

	matches := make(chan *IOC)

	ctxMatching, cancelMatching := context.WithCancel(ctx)
	// TODO: Add support for maxMatchLengths
	matchesRaw := ruleSet.GetMatchedDataReader(ctxMatching, ioutil.NopCloser(reader), nil)

	go func() {
		defer cancelMatching()
		defer close(matches)

		for match := range matchesRaw {
			ioc := &IOC{IOC: string(match.Data)}
			// Find what type this is
			for t, rule := range iocRegexes {
				if rule.String() == match.Rule.String() {
					ioc.Type = t
				}
			}

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
