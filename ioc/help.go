package ioc

import (
	"sort"

	"github.com/mpvl/unique"
)

// uniqueStringSlice Make slice contain only unique values
func uniqueStringSlice(slice []string) []string {
	if len(slice) <= 1 {
		return slice
	}

	// Duplicate and sort
	strings := slice
	sort.Strings(strings)
	unique.Strings(&strings)

	return strings
}
