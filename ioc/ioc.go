package ioc

import (
	"context"
	"io"
	"sort"
)

const (
	maxHTMLRecursionDepth = 100

	// DefaultMaxMatchLength is the default maximum length (in bytes) of a single
	// match when scanning a reader. It bounds how many bytes are retained between
	// reads so a match spanning a chunk boundary can still be found. Matches longer
	// than the effective limit that also straddle a boundary may be truncated.
	DefaultMaxMatchLength = 1024

	// readerChunkSize is how many bytes we attempt to read from the reader per read.
	readerChunkSize = 4096
)

// MaxMatchLengths allows overriding the max match length (see DefaultMaxMatchLength)
// for specific IOC types. The largest value across all types (or the default) is used
// as the sliding-window retain size in GetIOCsReader.
var MaxMatchLengths = map[Type]int{}

// readerMatchLimit returns the retain size used while scanning a reader.
func readerMatchLimit() int {
	limit := DefaultMaxMatchLength
	for _, v := range MaxMatchLengths {
		if v > limit {
			limit = v
		}
	}
	if limit < 1 {
		limit = 1
	}
	return limit
}

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

// dedupKey uniquely identifies an emitted IOC while scanning a reader.
type dedupKey struct {
	t Type
	s string
}

// readerMatch is an emitted IOC plus the byte offset of its first occurrence.
type readerMatch struct {
	ioc    *IOC
	offset int64
}

// GetIOCsReader finds IOCs in a stream, sending each unique IOC on the matches channel.
// The caller owns the channel and any concurrency (this function only sends).
//
// It performs a single pass over the reader using a sliding window: enough trailing
// bytes are retained between reads that matches spanning a chunk boundary survive, and
// matches are deduped across the overlapping windows. Output ordering is deterministic
// (by first byte offset, then type) regardless of how the reader chunks its data.
//
// Read errors and context cancellation surface via the returned error rather than being
// silently treated as end-of-stream.
func GetIOCsReader(ctx context.Context, reader io.Reader, getFangedIOCs bool, matches chan *IOC) error {
	retain := readerMatchLimit()

	var (
		window      []byte
		windowStart int64
		seen        = map[dedupKey]struct{}{}
		results     []*readerMatch
	)

	// record scans window for all IOC regexes. Only matches ending at or before
	// safeLen are committed; matches ending past safeLen are "deferred" — they may
	// still grow once more data arrives, so committing them now could truncate a
	// greedy match. A safeLen < 0 means "commit everything" (final flush at EOF).
	//
	// It returns the smallest start offset of any deferred match (so the caller never
	// trims those bytes away), and the spans of committed matches (so the caller never
	// trims through the *middle* of one — leaving a suffix that could re-match as a
	// different, truncated IOC).
	record := func(safeLen int) (keepFrom int, committed [][2]int) {
		keepFrom = len(window)
		for _, iocType := range Types {
			regex := iocRegexes[iocType]
			for _, loc := range regex.FindAllIndex(window, -1) {
				if safeLen >= 0 && loc[1] > safeLen {
					if loc[0] < keepFrom {
						keepFrom = loc[0]
					}
					continue
				}
				committed = append(committed, [2]int{loc[0], loc[1]})

				s := string(window[loc[0]:loc[1]])
				key := dedupKey{iocType, s}
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}

				ioc := &IOC{IOC: s, Type: iocType}
				if !ioc.IsFanged() || getFangedIOCs {
					results = append(results, &readerMatch{
						ioc:    ioc,
						offset: windowStart + int64(loc[0]),
					})
				}
			}
		}
		return keepFrom, committed
	}

	// keep is the number of trailing bytes retained after each scan so that matches
	// spanning a boundary survive; process only once we have keep plus a full safe zone
	// so scans happen in retain-sized batches rather than on every short read.
	keep := 2 * retain
	threshold := keep + retain

	buf := make([]byte, readerChunkSize)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			window = append(window, buf[:n]...)
			for len(window) >= threshold {
				safeLen := len(window) - retain
				keepFrom, committed := record(safeLen)

				trim := len(window) - keep
				if keepFrom < trim {
					trim = keepFrom
				}
				// Never trim through the middle of a committed match (which would
				// leave a suffix that can re-match as a different, truncated IOC).
				// Pull trim back to the start of any span it splits, to a fixpoint.
				for changed := true; changed; {
					changed = false
					for _, sp := range committed {
						if sp[0] < trim && trim < sp[1] {
							trim = sp[0]
							changed = true
						}
					}
				}
				if trim <= 0 {
					break
				}
				windowStart += int64(trim)
				window = append(window[:0], window[trim:]...)
			}
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			// Surface reader errors instead of silently ending the stream.
			return err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
	}

	// Final flush: commit everything left in the window.
	record(-1)

	// Deterministic ordering independent of chunk boundaries.
	sort.Slice(results, func(i, j int) bool {
		if results[i].offset != results[j].offset {
			return results[i].offset < results[j].offset
		}
		if results[i].ioc.Type != results[j].ioc.Type {
			return results[i].ioc.Type < results[j].ioc.Type
		}
		return results[i].ioc.IOC < results[j].ioc.IOC
	})

	for _, r := range results {
		select {
		case matches <- r.ioc:
		case <-ctx.Done():
			return ctx.Err()
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
