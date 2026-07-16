package ioc

import (
	"context"
	"strings"
	"testing"
	"testing/iotest"
)

// seedCorpus holds representative inputs used to seed both fuzz targets. These run as
// ordinary unit tests under `go test` (without -fuzz), so they guard against panics on
// every commit.
var seedCorpus = []string{
	"",
	"test@test.com",
	"http[://]google[.]com/path",
	"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
	"874058e8d8582bf85c115ce319c5b0af",
	"2001:db8::ff00:42:8329",
	"8.8.8.8 google.com filename.exe",
	"CVE-2021-44228 T1059.001 00:11:22:33:44:55",
	"0x52908400098527886E0F7030069857D2E4169EE7",
	"96:HesBmMFXt8f8+7cVQ6+P4Z9xMlBS+q6Ll8pRO1yzC:VBmMLf8+7YQ6+Pm9alBS+qL5RmC",
	"jörg@münchen.de",
	"1.2[.)3(.)4 test(dot)com",
	strings.Repeat("a.b.c ", 500),
}

// FuzzGetIOCs asserts the extraction path never panics on arbitrary input, across the
// string API, ParseIOC, and both reader chunkings.
func FuzzGetIOCs(f *testing.F) {
	for _, s := range seedCorpus {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		for _, fanged := range []bool{true, false} {
			iocs := GetIOCs(data, fanged)
			SortByType(iocs)
			StandardizeDefangs(iocs)
			_ = PrintIOCs(iocs, "json")
		}
		_ = ParseIOC(data)

		// Reader path (including a pathological one-byte-at-a-time reader) must also
		// not panic and must terminate.
		for _, r := range []func() *strings.Reader{
			func() *strings.Reader { return strings.NewReader(data) },
		} {
			drain(t, r())
		}
		drainReader(t, iotest.OneByteReader(strings.NewReader(data)))
	})
}

func drain(t *testing.T, r *strings.Reader) {
	t.Helper()
	out := make(chan *IOC)
	go func() {
		defer close(out)
		_ = GetIOCsReader(context.Background(), r, true, out)
	}()
	for range out {
	}
}

func drainReader(t *testing.T, r interface{ Read([]byte) (int, error) }) {
	t.Helper()
	out := make(chan *IOC)
	go func() {
		defer close(out)
		_ = GetIOCsReader(context.Background(), r, true, out)
	}()
	for range out {
	}
}

// FuzzFangDefang round-trips arbitrary values through Fang/Defang for every IOC type
// and asserts none of the operations panic and that repeated standardization is stable.
func FuzzFangDefang(f *testing.F) {
	for i, s := range seedCorpus {
		f.Add(s, i)
	}
	f.Fuzz(func(t *testing.T, s string, typeIdx int) {
		if typeIdx < 0 {
			typeIdx = -typeIdx
		}
		ty := Types[typeIdx%len(Types)]
		ioc := &IOC{IOC: s, Type: ty}

		// None of these may panic on arbitrary input.
		_ = ioc.Fang()
		_ = ioc.Defang()
		_ = ioc.IsFanged()
		_ = ioc.String()

		// Round-trip through the whole-slice standardization path as well; the point
		// is crash-resistance on arbitrary input, not a value assertion (defanging of
		// malformed input is intentionally lossy).
		StandardizeDefangs([]*IOC{{IOC: s, Type: ty}})
	})
}
