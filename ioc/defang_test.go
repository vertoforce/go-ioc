package ioc

import (
	"reflect"
	"testing"
)

type DefangTest struct {
	input *IOC
	want  *IOC
}

var DefangTests = []DefangTest{
	// Bitcoin n/a
	// Hashes n/a
	// Domains
	{&IOC{"test.com", Domain}, &IOC{"test[.]com", Domain}},
	{&IOC{"test.two.three.test.com", Domain}, &IOC{"test[.]two[.]three[.]test[.]com", Domain}},
	// Emails
	{&IOC{"Email@test.com", Email}, &IOC{"Email[AT]test[.]com", Email}},
	{&IOC{"test@test.test2.com", Email}, &IOC{"test[AT]test[.]test2[.]com", Email}},
	// IPv4
	{&IOC{"1.1.1.1", IPv4}, &IOC{"1[.]1[.]1[.]1", IPv4}},
	{&IOC{"1.2.3.4", IPv4}, &IOC{"1[.]2[.]3[.]4", IPv4}},
	{&IOC{"255.255.255.255", IPv4}, &IOC{"255[.]255[.]255[.]255", IPv4}},
	// IPv6
	{&IOC{"::1", IPv6}, &IOC{"[:][:]1", IPv6}},
	{&IOC{"1234::4321", IPv6}, &IOC{"1234[:][:]4321", IPv6}},
	{&IOC{"2001:0db8:0000:0000:0000:8a2e:0370:7334", IPv6}, &IOC{"2001[:]0db8[:]0000[:]0000[:]0000[:]8a2e[:]0370[:]7334", IPv6}},
	// URLs
	{&IOC{"http://URL.com/URL_name", URL}, &IOC{"hxxp[://]URL[.]com/URL_name", URL}},
	{&IOC{"http://test.URL.com/URL_name", URL}, &IOC{"hxxp[://]test[.]URL[.]com/URL_name", URL}},
	{&IOC{"http://URL.com/URL_name.name", URL}, &IOC{"hxxp[://]URL[.]com/URL_name[.]name", URL}},
	// Files n/a
	// Utility n/a
}

// TestDefang Test defanging using our standard defangs
func TestDefang(t *testing.T) {
	for _, test := range DefangTests {
		if got := test.input.Defang(); !reflect.DeepEqual(got, test.want) {
			t.Errorf("IOC %v expected %v but got %v", test.input.IOC, test.want, got.IOC)
		}
	}
}

var FangTests = []DefangTest{
	// Bitcoin n/a
	// Hashes n/a
	{
		&IOC{"4375747cfd5c5ce3bb5819d82256300874f662c5db0f902a62ed4ed56901c203", SHA256},
		&IOC{"4375747cfd5c5ce3bb5819d82256300874f662c5db0f902a62ed4ed56901c203", SHA256},
	},
	{
		&IOC{"bcc21abb9d4ff575cf805bddbc5566a0f0bb28c740f99478b50d4b41b00b51b1", SHA256},
		&IOC{"bcc21abb9d4ff575cf805bddbc5566a0f0bb28c740f99478b50d4b41b00b51b1", SHA256},
	},
	// Domains
	{&IOC{"test(.)com", Domain}, &IOC{"test.com", Domain}},
	{&IOC{"test(dot)com", Domain}, &IOC{"test.com", Domain}},
	{&IOC{"test[dot]com", Domain}, &IOC{"test.com", Domain}},
	{&IOC{"test.com", Domain}, &IOC{"test.com", Domain}},
	{&IOC{"test(.)two(.)three(.)test(.)com", Domain}, &IOC{"test.two.three.test.com", Domain}},
	{&IOC{"test(dot)two(dot)three(dot)test(.)com", Domain}, &IOC{"test.two.three.test.com", Domain}},
	// Emails
	{&IOC{"Email(AT)test(.)com", Email}, &IOC{"Email@test.com", Email}},
	{&IOC{"EmailATtest.com", Email}, &IOC{"Email@test.com", Email}},
	{&IOC{"Email at test.com", Email}, &IOC{"Email@test.com", Email}},
	{&IOC{"Email@test[.]com", Email}, &IOC{"Email@test.com", Email}},
	{&IOC{"test(AT)test(.)test2(.)com", Email}, &IOC{"test@test.test2.com", Email}},
	// IPv4
	{&IOC{"1[.]1[.]1[.]1", IPv4}, &IOC{"1.1.1.1", IPv4}},
	{&IOC{"1[.]2[.]3[.]4", IPv4}, &IOC{"1.2.3.4", IPv4}},
	{&IOC{"255[.]255[.]255[.]255", IPv4}, &IOC{"255.255.255.255", IPv4}},
	// IPv6
	{&IOC{"[:][:]1", IPv6}, &IOC{"::1", IPv6}},
	{&IOC{"1234[:][:]4321", IPv6}, &IOC{"1234::4321", IPv6}},
	{&IOC{"2001[:]0db8[:]0000[:]0000[:]0000[:]8a2e[:]0370[:]7334", IPv6}, &IOC{"2001:0db8:0000:0000:0000:8a2e:0370:7334", IPv6}},
	// URLs
	{&IOC{"hxxp[://]URL[.]com/URL_name", URL}, &IOC{"http://URL.com/URL_name", URL}},
	{&IOC{"hxxp[://]test[.]URL[.]com/URL_name", URL}, &IOC{"http://test.URL.com/URL_name", URL}},
	{&IOC{"hxxp[://]URL[.]com/URL_name[.]name", URL}, &IOC{"http://URL.com/URL_name.name", URL}},
	// Files n/a
	// Utility n/a
}

func TestFang(t *testing.T) {
	// Test all the defanging tests
	for _, test := range DefangTests {
		// Do this kinda in reverse
		t.Run(test.input.IOC, func(t *testing.T) {
			if got := test.want.Fang(); !reflect.DeepEqual(got, test.input) {
				t.Errorf("IOC %v expected %v but got %v", test.want.IOC, test.input.IOC, got.IOC)
			}
		})

	}

	// Now handle all the fang tests
	for _, test := range FangTests {
		t.Run(test.input.IOC, func(t *testing.T) {
			if got := test.input.Fang(); !reflect.DeepEqual(got, test.want) {
				t.Errorf("IOC %v expected %v but got %v", test.input.IOC, test.want.IOC, got.IOC)
			}
		})

	}
}

func TestIsFanged(t *testing.T) {
	tests := []struct {
		input *IOC
		want  bool
	}{
		// IPv4
		{&IOC{"1.2.3.4", IPv4}, true},
		{&IOC{"1(.)2.3(.)4", IPv4}, false},
		{&IOC{"1.2[.]3.4", IPv4}, false},
		{&IOC{"1.2.3.4", IPv4}, true},

		// Email
		{&IOC{"test@example.com", Email}, true},
		{&IOC{"test[@]example.com", Email}, false},
		{&IOC{"test(@)example.com", Email}, false},
		{&IOC{"test(@)example[.]com", Email}, false},

		// Domain
		{&IOC{"example.com", Domain}, true},
		{&IOC{"example(.)com", Domain}, false},
		{&IOC{"example[.]com", Domain}, false},
		{&IOC{"example(dot)com", Domain}, false},
		{&IOC{"example[dot]com", Domain}, false},

		// IPv6
		{&IOC{"::1", IPv6}, true},
		{&IOC{"[:][:]1", IPv6}, false},
		{&IOC{"1234[:][:]4321", IPv6}, false},
		{&IOC{"2001[:]0db8[:]0000[:]0000[:]0000[:]8a2e[:]0370[:]7334", IPv6}, false},

		// URLs
		{&IOC{"http://URL.com/URL_name", URL}, true},
		{&IOC{"hxxp[://]URL[.]com/URL_name", URL}, false},
		{&IOC{"hxxp[://]test[.]URL[.]com/URL_name", URL}, false},
		{&IOC{"hxxp[://]URL[.]com/URL_name[.]name", URL}, false},

		// Never fanged types
		// Bitcoin
		{&IOC{"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", Bitcoin}, false},
		// Hashes
		{&IOC{"874058e8d8582bf85c115ce319c5b0af", MD5}, false},
		// Files n/a
		{&IOC{"test.exe", File}, false},
		// CVE
		{&IOC{"CVE-2016-00000", CVE}, false},
	}

	for _, test := range tests {
		if test.input.IsFanged() != test.want {
			t.Errorf("Incorrect fanging result for " + test.input.String())
		}
	}
}
