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
	iocs := GetIOCs(ioc, true)
	ret := &IOC{}
	for _, ioc := range iocs {
		// Only return the "highest" IOC
		if ioc.Type > ret.Type {
			ret = ioc
		}
	}

	return ret
}

// GetIOCs Return a slice of IOCs from the provided data.
// getFangedIOCs will also return IOCs that are fanged (ex: google.com).
func GetIOCs(data string, getFangedIOCs bool) []*IOC {
	var iocs []*IOC

	// Loop through the types to find and search the provided data
	for iocType, regex := range iocRegexes {
		matches := uniqueStringSlice(regex.FindAllString(data, -1))
		for _, match := range matches {
			ioc := &IOC{IOC: match, Type: iocType}

			// Only add if defanged or we are getting all fanged IOCs
			if !ioc.IsFanged() || getFangedIOCs {
				iocs = append(iocs, ioc)
			}
		}
	}

	return iocs
}

// GetIOCsReader Get iocs from reader
// TODO: This is not deterministic output
func GetIOCsReader(ctx context.Context, reader io.Reader, getFangedIOCs bool, matches chan *IOC) error {
	// Combine all rules in to a RuleSet
	ruleSet := multiregex.RuleSet{}
	for _, rule := range iocRegexes {
		ruleSet = append(ruleSet, rule)
	}

	// TODO: Add support for maxMatchLengths
	matchesRaw := ruleSet.GetMatchedDataReader(ctx, ioutil.NopCloser(reader), nil)
	for match := range matchesRaw {
		// Check context
		if ctx.Err() != nil {
			return ctx.Err()
		}

		ioc := &IOC{IOC: string(match.Data)}
		// Find what type this is
		for t, rule := range iocRegexes {
			if rule.String() == match.Rule.String() {
				ioc.Type = t
			}
		}

		// Only add if defanged or we are getting all fanged IOCs
		if !ioc.IsFanged() || getFangedIOCs {
			select {
			case matches <- ioc:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return nil
}

// StandardizeDefangs will run all IOCs through a Fang() then Defang(), which will make all
// the IOCs of the same defanged style.
func StandardizeDefangs(iocs []*IOC) {
	for i, ioc := range iocs {
		iocs[i] = ioc.Fang().Defang()
	}
}
