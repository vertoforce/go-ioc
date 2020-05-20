package ioc

import (
	"sort"
)

// uniqueStringSlice Make slice contain only unique values
func uniqueStringSlice(slice []string) []string {
	if len(slice) <= 1 {
		return slice
	}

	//Duplicate and sort
	copy := slice
	sort.StringSlice(copy).Sort()

	// Return copied without duplicates
	i := 0
	for j := 1; j < len(copy); j++ {
		if copy[i] == copy[j] {
			// duplicate element, move on
			continue
		}
		copy[i+1] = copy[j]
		i++
	}

	return copy[0 : i+1]
}
