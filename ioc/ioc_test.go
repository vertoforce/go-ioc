package ioc

import (
	"context"
	"reflect"
	"strings"
	"testing"

	testify "github.com/stretchr/testify/assert"
)

func TestParseIOC(t *testing.T) {
	tests := []struct {
		ioc  string
		want *IOC
	}{
		{
			"test@test.com",
			&IOC{Type: Email, IOC: "test@test.com"},
		},
		{
			"https://test.com/asdf",
			&IOC{Type: URL, IOC: "https://test.com/asdf"},
		},
	}

	for i, test := range tests {
		if out := ParseIOC(test.ioc); !reflect.DeepEqual(out, test.want) {
			t.Errorf("Error on test %d", i)
		}
	}
}

func TestGetIOCs(t *testing.T) {
	// Test without standardizing defangs
	tests := []struct {
		input string
		want  []*IOC
	}{
		// Bitcoin
		{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", []*IOC{{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Bitcoin}}},
		{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\"", []*IOC{{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Bitcoin}}},
		{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2:", []*IOC{{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Bitcoin}}},
		{"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", []*IOC{{"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", Bitcoin}}},
		{"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", []*IOC{{"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", Bitcoin}}},
		// Hashes
		{"874058e8d8582bf85c115ce319c5b0af", []*IOC{{"874058e8d8582bf85c115ce319c5b0af", MD5}}},
		{"751641b4e4e6cc30f497639eee583b5b392451fb", []*IOC{{"751641b4e4e6cc30f497639eee583b5b392451fb", SHA1}}},
		{"4708a032833b054e4237392c4d75e41b4775dc67845e939487ab39f92de847ce", []*IOC{{"4708a032833b054e4237392c4d75e41b4775dc67845e939487ab39f92de847ce", SHA256}}},
		{"b4ae21eb1e337658368add0d2c177eb366123c8f961325dd1e67492acac84261be29594c1260bb3f249a3dcdf0372e381f2a23c4d026a91b4a7d66c949ddffad", []*IOC{{"b4ae21eb1e337658368add0d2c177eb366123c8f961325dd1e67492acac84261be29594c1260bb3f249a3dcdf0372e381f2a23c4d026a91b4a7d66c949ddffad", SHA512}}},
		{"874058e8d8582bf85c115ce319c5b0a", nil},

		// IPs
		{"8.8.8.8", []*IOC{{"8.8.8.8", IPv4}}},
		{"\"8.8.8.8\"", []*IOC{{"8.8.8.8", IPv4}}},
		{"1.1.1.1", []*IOC{{"1.1.1.1", IPv4}}},
		{"1(.)1.1(.)1", []*IOC{{"1(.)1.1(.)1", IPv4}}},
		{"1(.)1(.)1(.)1", []*IOC{{"1(.)1(.)1(.)1", IPv4}}},
		{"1(.)1[.]1(.)1", []*IOC{{"1(.)1[.]1(.)1", IPv4}}},
		{"10(.)252[.]255(.)255", []*IOC{{"10(.)252[.]255(.)255", IPv4}}},
		{"1.1[.]1[.]1", []*IOC{{"1.1[.]1[.]1", IPv4}}},
		{"1.2[.)3.4", []*IOC{{"1.2[.)3.4", IPv4}}},
		{"1.2[.)3(.)4", []*IOC{{"1.2[.)3(.)4", IPv4}}},
		{"1.2([.])3.4", nil},
		{"2001:0db8:0000:0000:0000:ff00:0042:8329", []*IOC{{"2001:0db8:0000:0000:0000:ff00:0042:8329", IPv6}}},
		{"2001:db8::ff00:42:8329", []*IOC{{"2001:db8::ff00:42:8329", IPv6}}},
		{"::1", []*IOC{{"::1", IPv6}}},
		{"10::1", []*IOC{{"10::1", IPv6}}},
		{"0010::1", []*IOC{{"0010::1", IPv6}}},
		{"300.300.300.300", nil},

		// Emails
		{"test@test.com", []*IOC{{"test.com", Domain}, {"test@test.com", Email}}},
		{"\"test@test.com\"", []*IOC{{"test.com", Domain}, {"test@test.com", Email}}},
		{"test[@]test.com", []*IOC{{"test.com", Domain}, {"test[@]test.com", Email}}},
		{"test(@)test.com", []*IOC{{"test.com", Domain}, {"test(@)test.com", Email}}},

		// Domains
		{"example.com", []*IOC{{"example.com", Domain}}},
		{"www.us-cert.gov", []*IOC{{"www.us-cert.gov", Domain}}},
		{"threat.int.test.blah.blahblah.blahblah.amazon.microsoft.test.com", []*IOC{{"threat.int.test.blah.blahblah.blahblah.amazon.microsoft.test.com", Domain}}},
		{"threat.int.test.blah.blahblah.blahblah.amazon.microsoft.test.com.invalid", []*IOC{{"threat.int.test.blah.blahblah.blahblah.amazon.microsoft.test.com", Domain}}},
		{"test(.)com", []*IOC{{"test(.)com", Domain}}},
		{"test[.]com", []*IOC{{"test[.]com", Domain}}},
		{"test(.)example(.)com", []*IOC{{"test(.)example(.)com", Domain}}},
		{"test(.)example[.]com", []*IOC{{"test(.)example[.]com", Domain}}},
		{"test(.]com", []*IOC{{"test(.]com", Domain}}},
		{"example.pumpkin", nil},

		// Links
		{"\"http://www.example.com/foo/bar?baz=1\"", []*IOC{{"www.example.com", Domain}, {"http://www.example.com/foo/bar?baz=1", URL}}},
		{"http://www.example.com/foo/bar?baz=1", []*IOC{{"www.example.com", Domain}, {"http://www.example.com/foo/bar?baz=1", URL}}},
		{"http://www.example.com", []*IOC{{"www.example.com", Domain}, {"http://www.example.com", URL}}},
		{"http[://]example.com/f", []*IOC{{"example.com", Domain}, {"http[://]example.com/f", URL}}},
		{"http://www.example.com/foo", []*IOC{{"www.example.com", Domain}, {"http://www.example.com/foo", URL}}},
		{"http://www.example.com/foo/", []*IOC{{"www.example.com", Domain}, {"http://www.example.com/foo", URL}}},
		{"https://www.example.com/foo/bar?baz=1", []*IOC{{"www.example.com", Domain}, {"https://www.example.com/foo/bar?baz=1", URL}}},
		{"https://www.example.com", []*IOC{{"www.example.com", Domain}, {"https://www.example.com", URL}}},
		{"https://www.example.com/foo", []*IOC{{"www.example.com", Domain}, {"https://www.example.com/foo", URL}}},
		{"https://www.example.com/foo/", []*IOC{{"www.example.com", Domain}, {"https://www.example.com/foo", URL}}},
		{"https://www[.]example[.]com/foo/", []*IOC{{"www[.]example[.]com", Domain}, {"https://www[.]example[.]com/foo", URL}}},
		{"https://www[.]example[.]com/foo/", []*IOC{{"www[.]example[.]com", Domain}, {"https://www[.]example[.]com/foo", URL}}},
		{"hxxps://185[.]159[.]82[.]15/hollyhole/c644[.]php", []*IOC{{"185[.]159[.]82[.]15", IPv4}, {"hxxps://185[.]159[.]82[.]15/hollyhole/c644[.]php", URL}}},

		// Files
		{"test.doc", []*IOC{{"test.doc", File}}},
		{"test.two.doc", []*IOC{{"test.two.doc", File}}},
		{"test.dll", []*IOC{{"test.dll", File}}},
		{"test.exe", []*IOC{{"test.exe", File}}},
		{"begin.test.test.exe", []*IOC{{"begin.test.test.exe", File}}},
		{"LOGSystem.Agent.Service.exe", []*IOC{{"LOGSystem.Agent.Service.exe", File}}},
		{"test.swf", []*IOC{{"test.swf", File}}},
		{"test.two.swf", []*IOC{{"test.two.swf", File}}},
		{"test.jpg", []*IOC{{"test.jpg", File}}},
		{"LOGSystem.Agent.Service.jpg", []*IOC{{"LOGSystem.Agent.Service.jpg", File}}},
		{"test.plist", []*IOC{{"test.plist", File}}},
		{"test.two.plist", []*IOC{{"test.two.plist", File}}},
		{"test.html", []*IOC{{"test.html", File}}},
		{"test.two.html", []*IOC{{"test.two.html", File}}},
		{"test.zip", []*IOC{{"test.zip", File}}},
		{"test.two.zip", []*IOC{{"test.two.zip", File}}},
		{"test.tar.gz", []*IOC{{"test.tar.gz", File}}},
		{"test.two.tar.gz", []*IOC{{"test.two.tar.gz", File}}},
		{".test.", nil},
		{"test.dl", nil},
		{"..", nil},
		{".", nil},
		{"example.pumpkin", nil},

		// Utility
		{"CVE-1800-0000", []*IOC{{"CVE-1800-0000", CVE}}},
		{"CVE-2016-0000", []*IOC{{"CVE-2016-0000", CVE}}},
		{"CVE-2100-0000", []*IOC{{"CVE-2100-0000", CVE}}},
		{"CVE-2016-00000", []*IOC{{"CVE-2016-00000", CVE}}},
		{"CVE-20100-0000", nil},
		{"CAPEC-13", []*IOC{{"CAPEC-13", CAPEC}}},
		{"CWE-200", []*IOC{{"CWE-200", CWE}}},
		{"cpe:2.3:a:openbsd:openssh:7.5:-:*:*:*:*:*:*", []*IOC{{"cpe:2.3:a:openbsd:openssh:7.5:-:*:*:*:*:*:*", CPE}}},
		{"cpe:/a:openbsd:openssh:7.5:-", []*IOC{{"cpe:/a:openbsd:openssh:7.5:-", CPE}}},
		{"cpe:/a:microsoft:internet_explorer:8.%02:sp%01", []*IOC{{"cpe:/a:microsoft:internet_explorer:8.%02:sp%01", CPE}}},
		{"cpe:/a:hp:insight_diagnostics:7.4.0.1570:-:~~online~win2003~x64~", []*IOC{{"cpe:/a:hp:insight_diagnostics:7.4.0.1570:-:~~online~win2003~x64~", CPE}}},
		{"cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*", []*IOC{{"cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*", CPE}}},
		{"cpe:2.3:a:microsoft:internet_explorer:8.*:sp?:*:*:*:*:*:*", []*IOC{{"cpe:2.3:a:microsoft:internet_explorer:8.*:sp?:*:*:*:*:*:*", CPE}}},
		{"cpe:2.3:a:hp:insight:7.4.0.1570:-:*:*:online:win2003:x64:*", []*IOC{{"cpe:2.3:a:hp:insight:7.4.0.1570:-:*:*:online:win2003:x64:*", CPE}}},
		{"cpe:2.3:a:hp:openview_network_manager:7.51:*:*:*:*:linux:*:*", []*IOC{{"cpe:2.3:a:hp:openview_network_manager:7.51:*:*:*:*:linux:*:*", CPE}}},
		{"cpe:2.3:a:foo\\\\bar:big\\$money_2010:*:*:*:*:special:ipod_touch:80gb:*", []*IOC{{"cpe:2.3:a:foo\\\\bar:big\\$money_2010:*:*:*:*:special:ipod_touch:80gb:*", CPE}}},

		// Misc
		{"1.1.1.1 google.com 1.1.1.1", []*IOC{
			{"google.com", Domain},
			{"1.1.1.1", IPv4},
		}},
		{"http://google.com/test/URL 1.3.2.1 Email@test.domain.com sogahgwugh4a49uhgaspd aiweawfa.asdas afw## )#@*)@$*(@ filename.exe", []*IOC{
			{"google.com", Domain},
			{"test.domain.com", Domain},
			{"Email@test.domain.com", Email},
			{"1.3.2.1", IPv4},
			{"http://google.com/test/URL", URL},
			{"filename.exe", File},
		}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			if iocs := GetIOCs(test.input, true, false); !testify.ElementsMatch(t, iocs, test.want) {
				t.Errorf("IOCType(%q), found %v =/= wanted %v", test.input, iocs, test.want)
			}
		})

	}
}
func TestStandardizedDefangs(t *testing.T) {
	testsStandardizedDefangs := []struct {
		input string
		want  []*IOC
	}{
		// IPs
		{"8.8.8.8", []*IOC{{"8[.]8[.]8[.]8", IPv4}}},
		{"\"8.8.8.8\"", []*IOC{{"8[.]8[.]8[.]8", IPv4}}},
		{"1.1.1.1", []*IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"1(.)1.1(.)1", []*IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"1(.)1(.)1(.)1", []*IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"1(.)1[.]1(.)1", []*IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"10(.)252[.]255(.)255", []*IOC{{"10[.]252[.]255[.]255", IPv4}}},
		{"1.1[.]1[.]1", []*IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"1.2[.)3.4", []*IOC{{"1[.]2[.]3[.]4", IPv4}}},
		{"1.2[.)3(.)4", []*IOC{{"1[.]2[.]3[.]4", IPv4}}},
	}

	for _, test := range testsStandardizedDefangs {
		t.Run(test.input, func(t *testing.T) {
			if iocs := GetIOCs(test.input, true, true); !reflect.DeepEqual(iocs, test.want) {
				t.Errorf("[standardizedDefang=true] IOCType(%q), found %v =/= wanted %v", test.input, iocs, test.want)
			}
		})

	}
}
func TestAllFanged(t *testing.T) {
	testsAllFanged := []struct {
		input string
		want  []*IOC
	}{
		// IPs
		{"8.8.8.8", nil},
		{"\"8.8.8.8\"", nil},
		{"1.1.1.1", nil},
		{"1(.)1.1(.)1", []*IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"1(.)1(.)1(.)1", []*IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"1(.)1[.]1(.)1", []*IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"10(.)252[.]255(.)255", []*IOC{{"10[.]252[.]255[.]255", IPv4}}},
		{"1.1[.]1[.]1", []*IOC{{"1[.]1[.]1[.]1", IPv4}}},
		{"1.2[.)3.4", []*IOC{{"1[.]2[.]3[.]4", IPv4}}},
		{"1.2[.)3(.)4", []*IOC{{"1[.]2[.]3[.]4", IPv4}}},
	}

	for _, test := range testsAllFanged {
		t.Run(test.input, func(t *testing.T) {
			if iocs := GetIOCs(test.input, false, true); !reflect.DeepEqual(iocs, test.want) {
				t.Errorf("[allFanged=false] IOCType(%q), found %v =/= wanted %v", test.input, iocs, test.want)
			}
		})
	}
}

func TestGetIOCsReader(t *testing.T) {
	// Test without standardizing defangs
	tests := []struct {
		input string
		want  []*IOC
	}{
		// Bitcoin
		{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", []*IOC{{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Bitcoin}}},
		{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\"", []*IOC{{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Bitcoin}}},
		{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2:", []*IOC{{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Bitcoin}}},
		{"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", []*IOC{{"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", Bitcoin}}},
		{"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", []*IOC{{"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", Bitcoin}}},
		// Hashes
		{"874058e8d8582bf85c115ce319c5b0af", []*IOC{{"874058e8d8582bf85c115ce319c5b0af", MD5}}},
		{"751641b4e4e6cc30f497639eee583b5b392451fb", []*IOC{{"751641b4e4e6cc30f497639eee583b5b392451fb", SHA1}}},
		{"4708a032833b054e4237392c4d75e41b4775dc67845e939487ab39f92de847ce", []*IOC{{"4708a032833b054e4237392c4d75e41b4775dc67845e939487ab39f92de847ce", SHA256}}},
		{"b4ae21eb1e337658368add0d2c177eb366123c8f961325dd1e67492acac84261be29594c1260bb3f249a3dcdf0372e381f2a23c4d026a91b4a7d66c949ddffad", []*IOC{{"b4ae21eb1e337658368add0d2c177eb366123c8f961325dd1e67492acac84261be29594c1260bb3f249a3dcdf0372e381f2a23c4d026a91b4a7d66c949ddffad", SHA512}}},
		{"874058e8d8582bf85c115ce319c5b0a", nil},

		// IPs
		{"8.8.8.8", []*IOC{{"8.8.8.8", IPv4}}},
		{"\"8.8.8.8\"", []*IOC{{"8.8.8.8", IPv4}}},
		{"1.1.1.1", []*IOC{{"1.1.1.1", IPv4}}},
		{"1(.)1.1(.)1", []*IOC{{"1(.)1.1(.)1", IPv4}}},
		{"1(.)1(.)1(.)1", []*IOC{{"1(.)1(.)1(.)1", IPv4}}},
		{"1(.)1[.]1(.)1", []*IOC{{"1(.)1[.]1(.)1", IPv4}}},
		{"10(.)252[.]255(.)255", []*IOC{{"10(.)252[.]255(.)255", IPv4}}},
		{"1.1[.]1[.]1", []*IOC{{"1.1[.]1[.]1", IPv4}}},
		{"1.2[.)3.4", []*IOC{{"1.2[.)3.4", IPv4}}},
		{"1.2[.)3(.)4", []*IOC{{"1.2[.)3(.)4", IPv4}}},
		{"1.2([.])3.4", nil},
		{"2001:0db8:0000:0000:0000:ff00:0042:8329", []*IOC{{"2001:0db8:0000:0000:0000:ff00:0042:8329", IPv6}}},
	}

	for _, test := range tests {

		t.Run(test.input, func(t *testing.T) {
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
		})
	}
}
