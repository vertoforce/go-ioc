package ioc

import (
	"strings"
	"testing"

	testify "github.com/stretchr/testify/assert"
)

// TestNewTypes covers the IOC types added after CPE plus the tightened IPv6 / ssdeep.
func TestNewTypes(t *testing.T) {
	tests := []struct {
		input string
		want  []*IOC
	}{
		// MITRE ATT&CK technique IDs
		{"T1059", []*IOC{{"T1059", MITRE}}},
		{"technique T1566.002 was used", []*IOC{{"T1566.002", MITRE}}},
		{"T123", nil},   // too short
		{"T12345", nil}, // too long

		// MAC addresses
		{"00:11:22:33:44:55", []*IOC{{"00:11:22:33:44:55", MAC}}},
		{"AA-BB-CC-DD-EE-FF", []*IOC{{"AA-BB-CC-DD-EE-FF", MAC}}},

		// Monero (standard 95-char address)
		{"44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
			[]*IOC{{"44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A", Monero}}},

		// Ethereum
		{"0x52908400098527886E0F7030069857D2E4169EE7", []*IOC{{"0x52908400098527886E0F7030069857D2E4169EE7", Ethereum}}},

		// ssdeep (re-enabled): must be recognized and NOT collide with IPv6
		{"96:HesBmMFXt8f8+7cVQ6+P4Z9xMlBS+q6Ll8pRO1yzC:VBmMLf8+7YQ6+Pm9alBS+qL5RmC",
			[]*IOC{{"96:HesBmMFXt8f8+7cVQ6+P4Z9xMlBS+q6Ll8pRO1yzC:VBmMLf8+7YQ6+Pm9alBS+qL5RmC", SSDeep}}},

		// IPv6 tightened: full "::"-compressed addresses match in full, and are NOT
		// also reported as ssdeep or MAC.
		{"2001:db8::ff00:42:8329", []*IOC{{"2001:db8::ff00:42:8329", IPv6}}},
		{"2001:0db8:0000:0000:0000:ff00:0042:8329", []*IOC{{"2001:0db8:0000:0000:0000:ff00:0042:8329", IPv6}}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got := GetIOCs(test.input, true)
			if !testify.ElementsMatch(t, got, test.want) {
				t.Errorf("GetIOCs(%q) = %v, want %v", test.input, got, test.want)
			}
		})
	}
}

// TestTypeStringComplete guards that every Type value stringifies (the generated
// stringer had previously fallen out of sync with the enum).
func TestTypeStringComplete(t *testing.T) {
	for _, ty := range Types {
		if got := ty.String(); got == "" || strings.HasPrefix(got, "Type(") {
			t.Errorf("Type %d has no stringer name: %q", ty, got)
		}
	}
	if SSDeep.String() != "SSDeep" || Ethereum.String() != "Ethereum" || CPE.String() != "CPE" {
		t.Errorf("stringer mismatch: SSDeep=%q Ethereum=%q CPE=%q", SSDeep.String(), Ethereum.String(), CPE.String())
	}
}
