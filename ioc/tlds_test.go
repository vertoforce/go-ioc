package ioc

import "testing"

// TestModernTLDs verifies that gTLDs added long after the original 2015-era snapshot
// are now recognized as domains, and that defanged dots still work with them.
func TestModernTLDs(t *testing.T) {
	fanged := []string{
		"myapp.app",
		"cool.dev",
		"storage.cloud",
		"archive.zip",
		"landing.page",
		"secret.onion", // IANA omits onion; we add it back
	}
	for _, in := range fanged {
		t.Run(in, func(t *testing.T) {
			// Some (myapp.app, archive.zip) are also valid file names; just assert the
			// Domain interpretation is present now that these are real gTLDs.
			iocs := GetIOCs(in, true)
			found := false
			for _, ioc := range iocs {
				if ioc.Type == Domain && ioc.IOC == in {
					found = true
				}
			}
			if !found {
				t.Errorf("expected Domain %q in %v", in, iocs)
			}
		})
	}

	// Defanged dot must still match against the modern TLDs.
	defanged := map[string]string{
		"cool[.]dev":     "cool[.]dev",
		"storage(.)cloud": "storage(.)cloud",
	}
	for in, want := range defanged {
		t.Run(in, func(t *testing.T) {
			iocs := GetIOCs(in, true)
			found := false
			for _, ioc := range iocs {
				if ioc.Type == Domain && ioc.IOC == want {
					found = true
				}
			}
			if !found {
				t.Errorf("expected defanged Domain %q in %v", want, iocs)
			}
		})
	}

	// onion is present even though IANA omits it.
	if !containsTLD("onion") {
		t.Error("onion TLD missing from generated list")
	}
	if !containsTLD("app") || !containsTLD("dev") || !containsTLD("cloud") || !containsTLD("zip") {
		t.Error("expected modern gTLDs missing from generated list")
	}
}

func containsTLD(t string) bool {
	for _, v := range tlds {
		if v == t {
			return true
		}
	}
	return false
}
