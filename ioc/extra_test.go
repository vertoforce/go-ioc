package ioc

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGetIOCsFromRSS(t *testing.T) {
	// Test failure
	_, err := GetIOCsFromRSS(context.Background(), "error")
	if err == nil {
		t.Errorf("Should have errored on that URL")
	}

	iocs, err := GetIOCsFromRSS(context.Background(), "https://www.anomali.com/site/blog-rss")
	if err != nil {
		t.Errorf(err.Error())
	}

	// TODO Add more checks
	if len(iocs) < 10 {
		t.Errorf("Possible error in fetching all IOCs from articles")
	}

}

func TestGetIOCsFromURL(t *testing.T) {
	// Test failure
	_, err := GetIOCsFromURLPage(nil)
	if err == nil {
		t.Errorf("Should have errored on that URL")
	}

	// Tests
	tests := []struct {
		URL          string
		ExpectedIOCs []*IOC
	}{
		{"https://blog.trendmicro.com/trendlabs-security-intelligence/latest-trickbot-campaign-delivered-via-highly-obfuscated-js-file/",
			[]*IOC{
				{"0242ebb681eb1b3dbaa751320dea56e31c5e52c8324a7de125a8144cc5270698", SHA256},
				{"16429e95922c9521f7a40fa8f4c866444a060122448b243444dd2358a96a344c", SHA256},
				{"666515eec773e200663fbd5fcad7109e9b97be11a83b41b8a4d73b7f5c8815ff", SHA256},
				{"41cd7fec5eaad44d2dba028164b9b9e2d1c6ea9d035679651b3b344542c40d45", SHA256},
				{"970b135b4c47c12f97bc3d3bbdf325f391b499d03fe19ac9313bcace3a1450d2", SHA256},
				{"8537d74885aed5cab758607e253a60433ef6410fd9b9b1c571ddabe6304bb68a", SHA256},
				{"AgentSimulator.exe", File},
				{"B.exe", File},
				{"BennyDB.exe", File},
				{"ctfmon.exe", File},
				{"iexplore.exe", File},
				{"LOGSystem.Agent.Service.exe", File},
				{"hxxps://185[.]159[.]82[.]15/hollyhole/c644[.]php", URL},
				// This does not represent all found IOCs, but some that definitely should be found
			}},
		{"https://www.anomali.com/blog/threat-actors-utilizing-ech0raix-ransomware-change-nas-targeting",
			[]*IOC{
				{"qkqkro6buaqoocv4[.]onion", Domain},
				{"16sYqXAncDDiijcuruZecCkdBDwDf4vSEC", Bitcoin},
				{"1N6JphHFaYmYaokS5xH31Z67bvk4ykd9CP", Bitcoin},
				{"1LZ1VNJfn6mWjPzkCyoBvqWaBZYXAwn135", Bitcoin},
				// This does not represent all found IOCs, but some that definitely should be found
			}},
	}

	for te := range tests {
		req, err := http.NewRequest("GET", tests[te].URL, nil)
		if err != nil {
			t.Errorf("Errored on this test: " + tests[te].URL)
			continue
		}
		iocs, err := GetIOCsFromURLPage(req)
		if err != nil {
			t.Errorf("Errored on this test: " + tests[te].URL)
		}
		// check to make sure we found each expected IOC
	outer:
		for e := range tests[te].ExpectedIOCs {
			for i := range iocs {
				if reflect.DeepEqual(iocs[i], tests[te].ExpectedIOCs[e]) {
					continue outer // We did, continue
				}
			}
			// We didn't find that IOC
			t.Errorf("We did not find this IOC: " + tests[te].ExpectedIOCs[e].IOC)
		}

		// Check if there are any duplicates
	outerloop:
		for i, ioc := range iocs {
			for k := i + 1; k < len(iocs); k++ {
				if ioc.IOC == iocs[k].IOC {
					t.Errorf("Found duplicate IOC: " + ioc.IOC)
					continue outerloop
				}
			}
		}
	}
}

func BenchmarkGetIOCsFromHTML(b *testing.B) {
	var articles []string
	err := filepath.Walk("articles", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("prevent panic by handling failure accessing a path %q: %v\n", path, err)
			return err
		}
		fileContentsB, err := ioutil.ReadFile(path)
		if err != nil {
			return nil
		}
		fileContents := string(fileContentsB)
		articles = append(articles, fileContents)
		return nil
	})
	if err != nil {
		b.Fatalf("Failed to walk files: %s", err)
	}
	for n := 0; n < b.N; n++ {
		for _, a := range articles {
			_, err = GetIOCsFromHTML(&a)
			if err != nil {
				b.Errorf("Failed to get IOCS from HTML: %s", err)
			}

		}
	}
}

// -- []IOC helpers --

func TestIOCsSortByType(t *testing.T) {
	tests := []struct {
		input []*IOC
		want  []*IOC
	}{
		{
			[]*IOC{
				{"1", Domain},
				{"4", URL},
				{"1", Domain},
				{"3", IPv4},
				{"4", URL},
				{"2", Email},
				{"0", Bitcoin},
				{"1", Domain},
				{"3", IPv4},
				{"0", Bitcoin},
				{"3", IPv4},
			}, []*IOC{
				{"0", Bitcoin},
				{"0", Bitcoin},
				{"1", Domain},
				{"1", Domain},
				{"1", Domain},
				{"2", Email},
				{"3", IPv4},
				{"3", IPv4},
				{"3", IPv4},
				{"4", URL},
				{"4", URL},
			},
		},
	}
	for i, test := range tests {
		if got := SortByType(test.input); !reflect.DeepEqual(got, test.want) {
			t.Errorf("Failed to get desired result on test " + fmt.Sprint(i))
		}
	}
}

func TestPrintIOCs(t *testing.T) {
	tests := []struct {
		input []*IOC
		want  string
	}{
		{
			[]*IOC{
				{"0", Bitcoin},
				{"1", Domain},
				{"2", Email},
				{"3", IPv4},
				{"4", URL},
			}, "0|Bitcoin\n1|Domain\n2|Email\n3|IPv4\n4|URL",
		},
	}

	for i, test := range tests {
		if got := PrintIOCs(test.input, "csv"); !reflect.DeepEqual(got, test.want) {
			t.Errorf("Failed to get desired result on test %d", i)
		}
	}
}

func TestGetIOCsStats(t *testing.T) {
	tests := []struct {
		input []*IOC
		want  map[Type]int
	}{
		{
			[]*IOC{
				{"0", Bitcoin},
				{"1", Bitcoin},
				{"2", Domain},
				{"3", Domain},
				{"4", Domain},
			}, map[Type]int{
				Bitcoin: 2,
				Domain:  3,
			},
		},
	}

	for i, test := range tests {
		if got := GetIOCsCounts(test.input); !reflect.DeepEqual(got, test.want) {
			t.Errorf("Failed to get desired result on test " + fmt.Sprint(i))
		}
	}
}
