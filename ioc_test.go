package ioc

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestGetIOCs(t *testing.T) {
	// Test without standardizing defangs
	tests := []struct {
		input string
		want  []IOC
	}{
		// Bitcoin
		{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", []IOC{{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Bitcoin}}},
		{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\"", []IOC{{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Bitcoin}}},
		{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2:", []IOC{{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Bitcoin}}},
		{"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", []IOC{{"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", Bitcoin}}},
		{"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", []IOC{{"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", Bitcoin}}},
		// Hashes
		{"874058e8d8582bf85c115ce319c5b0af", []IOC{{"874058e8d8582bf85c115ce319c5b0af", MD5}}},
		{"751641b4e4e6cc30f497639eee583b5b392451fb", []IOC{{"751641b4e4e6cc30f497639eee583b5b392451fb", SHA1}}},
		{"4708a032833b054e4237392c4d75e41b4775dc67845e939487ab39f92de847ce", []IOC{{"4708a032833b054e4237392c4d75e41b4775dc67845e939487ab39f92de847ce", SHA256}}},
		{"b4ae21eb1e337658368add0d2c177eb366123c8f961325dd1e67492acac84261be29594c1260bb3f249a3dcdf0372e381f2a23c4d026a91b4a7d66c949ddffad", []IOC{{"b4ae21eb1e337658368add0d2c177eb366123c8f961325dd1e67492acac84261be29594c1260bb3f249a3dcdf0372e381f2a23c4d026a91b4a7d66c949ddffad", SHA512}}},
		{"874058e8d8582bf85c115ce319c5b0a", nil},

		// IPs
		{"8.8.8.8", []IOC{{"8.8.8.8", IPv4}}},
		{"\"8.8.8.8\"", []IOC{{"8.8.8.8", IPv4}}},
		{"1.1.1.1", []IOC{{"1.1.1.1", IPv4}}},
		{"1(.)1.1(.)1", []IOC{{"1(.)1.1(.)1", IPv4}}},
		{"1(.)1(.)1(.)1", []IOC{{"1(.)1(.)1(.)1", IPv4}}},
		{"1(.)1[.]1(.)1", []IOC{{"1(.)1[.]1(.)1", IPv4}}},
		{"10(.)252[.]255(.)255", []IOC{{"10(.)252[.]255(.)255", IPv4}}},
		{"1.1[.]1[.]1", []IOC{{"1.1[.]1[.]1", IPv4}}},
		{"1.2[.)3.4", []IOC{{"1.2[.)3.4", IPv4}}},
		{"1.2[.)3(.)4", []IOC{{"1.2[.)3(.)4", IPv4}}},
		{"1.2([.])3.4", nil},
		{"2001:0db8:0000:0000:0000:ff00:0042:8329", []IOC{{"2001:0db8:0000:0000:0000:ff00:0042:8329", IPv6}}},
		{"2001:db8::ff00:42:8329", []IOC{{"2001:db8::ff00:42:8329", IPv6}}},
		{"::1", []IOC{{"::1", IPv6}}},
		{"10::1", []IOC{{"10::1", IPv6}}},
		{"0010::1", []IOC{{"0010::1", IPv6}}},
		{"300.300.300.300", nil},

		// Emails
		{"test@test.com", []IOC{{"test.com", Domain}, {"test@test.com", Email}}},
		{"\"test@test.com\"", []IOC{{"test.com", Domain}, {"test@test.com", Email}}},
		{"test[@]test.com", []IOC{{"test.com", Domain}, {"test[@]test.com", Email}}},
		{"test(@)test.com", []IOC{{"test.com", Domain}, {"test(@)test.com", Email}}},

		// Domains
		{"example.com", []IOC{{"example.com", Domain}}},
		{"www.us-cert.gov", []IOC{{"www.us-cert.gov", Domain}}},
		{"threat.int.test.blah.blahblah.blahblah.amazon.microsoft.test.com", []IOC{{"threat.int.test.blah.blahblah.blahblah.amazon.microsoft.test.com", Domain}}},
		{"threat.int.test.blah.blahblah.blahblah.amazon.microsoft.test.com.invalid", []IOC{{"threat.int.test.blah.blahblah.blahblah.amazon.microsoft.test.com", Domain}}},
		{"test(.)com", []IOC{{"test(.)com", Domain}}},
		{"test[.]com", []IOC{{"test[.]com", Domain}}},
		{"test(.)example(.)com", []IOC{{"test(.)example(.)com", Domain}}},
		{"test(.)example[.]com", []IOC{{"test(.)example[.]com", Domain}}},
		{"test(.]com", []IOC{{"test(.]com", Domain}}},
		{"example.pumpkin", nil},

		// Links
		{"\"http://www.example.com/foo/bar?baz=1\"", []IOC{{"www.example.com", Domain}, {"http://www.example.com/foo/bar?baz=1", URL}}},
		{"http://www.example.com/foo/bar?baz=1", []IOC{{"www.example.com", Domain}, {"http://www.example.com/foo/bar?baz=1", URL}}},
		{"http://www.example.com", []IOC{{"www.example.com", Domain}, {"http://www.example.com", URL}}},
		{"http[://]example.com/f", []IOC{{"example.com", Domain}, {"http[://]example.com/f", URL}}},
		{"http://www.example.com/foo", []IOC{{"www.example.com", Domain}, {"http://www.example.com/foo", URL}}},
		{"http://www.example.com/foo/", []IOC{{"www.example.com", Domain}, {"http://www.example.com/foo", URL}}},
		{"https://www.example.com/foo/bar?baz=1", []IOC{{"www.example.com", Domain}, {"https://www.example.com/foo/bar?baz=1", URL}}},
		{"https://www.example.com", []IOC{{"www.example.com", Domain}, {"https://www.example.com", URL}}},
		{"https://www.example.com/foo", []IOC{{"www.example.com", Domain}, {"https://www.example.com/foo", URL}}},
		{"https://www.example.com/foo/", []IOC{{"www.example.com", Domain}, {"https://www.example.com/foo", URL}}},
		{"https://www[.]example[.]com/foo/", []IOC{{"www[.]example[.]com", Domain}, {"https://www[.]example[.]com/foo", URL}}},
		{"https://www[.]example[.]com/foo/", []IOC{{"www[.]example[.]com", Domain}, {"https://www[.]example[.]com/foo", URL}}},
		{"hxxps://185[.]159[.]82[.]15/hollyhole/c644[.]php", []IOC{{"185[.]159[.]82[.]15", IPv4}, {"hxxps://185[.]159[.]82[.]15/hollyhole/c644[.]php", URL}}},

		// Files
		{"test.doc", []IOC{{"test.doc", File}}},
		{"test.two.doc", []IOC{{"test.two.doc", File}}},
		{"test.dll", []IOC{{"test.dll", File}}},
		{"test.exe", []IOC{{"test.exe", File}}},
		{"begin.test.test.exe", []IOC{{"begin.test.test.exe", File}}},
		{"LOGSystem.Agent.Service.exe", []IOC{{"LOGSystem.Agent.Service.exe", File}}},
		{"test.swf", []IOC{{"test.swf", File}}},
		{"test.two.swf", []IOC{{"test.two.swf", File}}},
		{"test.jpg", []IOC{{"test.jpg", File}}},
		{"LOGSystem.Agent.Service.jpg", []IOC{{"LOGSystem.Agent.Service.jpg", File}}},
		{"test.plist", []IOC{{"test.plist", File}}},
		{"test.two.plist", []IOC{{"test.two.plist", File}}},
		{"test.html", []IOC{{"test.html", File}}},
		{"test.two.html", []IOC{{"test.two.html", File}}},
		{"test.zip", []IOC{{"test.zip", File}}},
		{"test.two.zip", []IOC{{"test.two.zip", File}}},
		{"test.tar.gz", []IOC{{"test.tar.gz", File}}},
		{"test.two.tar.gz", []IOC{{"test.two.tar.gz", File}}},
		{".test.", nil},
		{"test.dl", nil},
		{"..", nil},
		{".", nil},
		{"example.pumpkin", nil},

		// Utility
		{"CVE-1800-0000", []IOC{{"CVE-1800-0000", CVE}}},
		{"CVE-2016-0000", []IOC{{"CVE-2016-0000", CVE}}},
		{"CVE-2100-0000", []IOC{{"CVE-2100-0000", CVE}}},
		{"CVE-2016-00000", []IOC{{"CVE-2016-00000", CVE}}},
		{"CVE-20100-0000", nil},

		// Misc
		{"1.1.1.1 google.com 1.1.1.1", []IOC{
			{"google.com", Domain},
			{"1.1.1.1", IPv4},
		}},
		{"http://google.com/test/URL 1.3.2.1 Email@test.domain.com sogahgwugh4a49uhgaspd aiweawfa.asdas afw## )#@*)@$*(@ filename.exe", []IOC{
			{"google.com", Domain},
			{"test.domain.com", Domain},
			{"Email@test.domain.com", Email},
			{"1.3.2.1", IPv4},
			{"http://google.com/test/URL", URL},
			{"filename.exe", File},
		}},
	}

	for _, test := range tests {
		if iocs := GetIOCs(test.input, true, false); !reflect.DeepEqual(iocs, test.want) {
			t.Errorf("IOCType(%q), found %v =/= wanted %v", test.input, iocs, test.want)
		}
	}

	testsStandardizedDefangs := []struct {
		input string
		want  []IOC
	}{
		// IPs
		{"8.8.8.8", []IOC{{"8[.]8[.]8[.]8", IPv4}}},
		{"\"8.8.8.8\"", []IOC{{"8[.]8[.]8[.]8", IPv4}}},
		{"1.1.1.1", []IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"1(.)1.1(.)1", []IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"1(.)1(.)1(.)1", []IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"1(.)1[.]1(.)1", []IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"10(.)252[.]255(.)255", []IOC{{"10[.]252[.]255[.]255", IPv4}}},
		{"1.1[.]1[.]1", []IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"1.2[.)3.4", []IOC{{"1[.]2[.]3[.]4", IPv4}}},
		{"1.2[.)3(.)4", []IOC{{"1[.]2[.]3[.]4", IPv4}}},
	}

	for _, test := range testsStandardizedDefangs {
		if iocs := GetIOCs(test.input, true, true); !reflect.DeepEqual(iocs, test.want) {
			t.Errorf("[standardizedDefang=true] IOCType(%q), found %v =/= wanted %v", test.input, iocs, test.want)
		}
	}

	testsAllFanged := []struct {
		input string
		want  []IOC
	}{
		// IPs
		{"8.8.8.8", nil},
		{"\"8.8.8.8\"", nil},
		{"1.1.1.1", nil},
		{"1(.)1.1(.)1", []IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"1(.)1(.)1(.)1", []IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"1(.)1[.]1(.)1", []IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"10(.)252[.]255(.)255", []IOC{{"10[.]252[.]255[.]255", IPv4}}},
		{"1.1[.]1[.]1", []IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"1.2[.)3.4", []IOC{{"1[.]2[.]3[.]4", IPv4}}},
		{"1.2[.)3(.)4", []IOC{{"1[.]2[.]3[.]4", IPv4}}},
	}

	for _, test := range testsAllFanged {
		if iocs := GetIOCs(test.input, false, true); !reflect.DeepEqual(iocs, test.want) {
			t.Errorf("[allFanged=false] IOCType(%q), found %v =/= wanted %v", test.input, iocs, test.want)
		}
	}
}

func TestGetIOCsReader(t *testing.T) {
	// Test without standardizing defangs
	tests := []struct {
		input string
		want  []IOC
	}{
		// Bitcoin
		{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", []IOC{{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Bitcoin}}},
		{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\"", []IOC{{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Bitcoin}}},
		{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2:", []IOC{{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Bitcoin}}},
		{"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", []IOC{{"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", Bitcoin}}},
		{"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", []IOC{{"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", Bitcoin}}},
		// Hashes
		{"874058e8d8582bf85c115ce319c5b0af", []IOC{{"874058e8d8582bf85c115ce319c5b0af", MD5}}},
		{"751641b4e4e6cc30f497639eee583b5b392451fb", []IOC{{"751641b4e4e6cc30f497639eee583b5b392451fb", SHA1}}},
		{"4708a032833b054e4237392c4d75e41b4775dc67845e939487ab39f92de847ce", []IOC{{"4708a032833b054e4237392c4d75e41b4775dc67845e939487ab39f92de847ce", SHA256}}},
		{"b4ae21eb1e337658368add0d2c177eb366123c8f961325dd1e67492acac84261be29594c1260bb3f249a3dcdf0372e381f2a23c4d026a91b4a7d66c949ddffad", []IOC{{"b4ae21eb1e337658368add0d2c177eb366123c8f961325dd1e67492acac84261be29594c1260bb3f249a3dcdf0372e381f2a23c4d026a91b4a7d66c949ddffad", SHA512}}},
		{"874058e8d8582bf85c115ce319c5b0a", nil},

		// IPs
		{"8.8.8.8", []IOC{{"8.8.8.8", IPv4}}},
		{"\"8.8.8.8\"", []IOC{{"8.8.8.8", IPv4}}},
		{"1.1.1.1", []IOC{{"1.1.1.1", IPv4}}},
		{"1(.)1.1(.)1", []IOC{{"1(.)1.1(.)1", IPv4}}},
		{"1(.)1(.)1(.)1", []IOC{{"1(.)1(.)1(.)1", IPv4}}},
		{"1(.)1[.]1(.)1", []IOC{{"1(.)1[.]1(.)1", IPv4}}},
		{"10(.)252[.]255(.)255", []IOC{{"10(.)252[.]255(.)255", IPv4}}},
		{"1.1[.]1[.]1", []IOC{{"1.1[.]1[.]1", IPv4}}},
		{"1.2[.)3.4", []IOC{{"1.2[.)3.4", IPv4}}},
		{"1.2[.)3(.)4", []IOC{{"1.2[.)3(.)4", IPv4}}},
		{"1.2([.])3.4", nil},
		{"2001:0db8:0000:0000:0000:ff00:0042:8329", []IOC{{"2001:0db8:0000:0000:0000:ff00:0042:8329", IPv6}}},
	}

	for _, test := range tests {
		iocs := GetIOCsReader(context.Background(), strings.NewReader(test.input), true, false)

	outer:
		for ioc := range iocs {
			for _, wantedIOC := range test.want {
				if ioc.IOC == wantedIOC.IOC && ioc.Type == wantedIOC.Type {
					continue outer
				}
			}
			t.Errorf("Did not find %v in what we wanted %v", ioc, test.want)
		}
	}
}
