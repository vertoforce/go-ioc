package ioc

import (
	"regexp"
	"strings"
)

//go:generate go run ../gen/tlds

// -- Regexes --
// This stemmed from Cacador with some changes and improvements
// https://github.com/sroberts/cacador

// domainRegex is built from the generated IANA TLD list (see tlds.go / gen/tlds).
// The label structure ([A-Za-z0-9-] with optional defang brackets around each dot)
// matches the original Cacador-derived pattern; only the TLD alternation is generated.
var domainRegex = `([A-Za-z0-9-]+([\[\(]?\.[\]\)]?[A-Za-z0-9-]+)*[\[\(]?\.[\]\)]?(` + strings.Join(tlds, "|") + `)\b)`

// iocRegexes List of regexes corresponding to a IOC
var iocRegexes = map[Type]*regexp.Regexp{
	// Bitcoin
	Bitcoin: regexp.MustCompile(`(?:^|[ '":])((bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39})`),
	// Hashes
	MD5:    regexp.MustCompile(`\b[A-Fa-f0-9]{32}\b`),
	SHA1:   regexp.MustCompile(`\b[A-Fa-f0-9]{40}\b`),
	SHA256: regexp.MustCompile(`\b[A-Fa-f0-9]{64}\b`),
	SHA512: regexp.MustCompile(`\b[A-Fa-f0-9]{128}\b`),
	// Domains
	Domain: regexp.MustCompile(domainRegex),
	// Emails
	// Widened per issue #4: allow unicode letters (\p{L}) in both the local part and the
	// domain so international addresses match, plus common local-part specials (+ % etc).
	Email: regexp.MustCompile(`[\p{L}0-9._%+-]+((\ ?(\[|\()?\ ?@\ ?(\)|\])?\ ?)|(\ ?(\[|\()\ ?[aA][tT]\ ?(\)|\])\ ?))[\p{L}0-9.-]+`),
	// IPs
	IPv4: regexp.MustCompile(`(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)([\[\(]?\.[\]\)]?)){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
	// IPv6 uses a strict comprehensive pattern compiled POSIX (leftmost-longest) so
	// that "::"-compressed addresses match in full. Tightening it (vs the old very loose
	// pattern) means it no longer collides with MAC addresses or ssdeep hashes, which
	// let us re-enable SSDeep below.
	IPv6: regexp.MustCompilePOSIX(`(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(:[0-9a-fA-F]{1,4}){1,6}|:((:[0-9a-fA-F]{1,4}){1,7}|:))`),
	// URLs
	URL: regexp.MustCompile(`(\b((http|https|hxxp|hxxps|nntp|ntp|rdp|sftp|smtp|ssh|tor|webdav|xmpp)[[([]?\:\/\/[])]?[\S]+)\b)`),
	// Files
	File: regexp.MustCompile(`(([\w\-]+)\.)+(docx|doc|csv|pdf|xlsx|xls|rtf|txt|pptx|ppt|pages|keynote|numbers|exe|dll|jar|flv|swf|jpeg|jpg|gif|png|tiff|bmp|plist|app|pkg|html|htm|php|jsp|asp|zip|zipx|7z|rar|tar|gz)`),
	// Utility
	CVE:   regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`),
	CAPEC: regexp.MustCompile(`(?i)CAPEC-\d+`),
	CWE:   regexp.MustCompile(`(?i)CWE-\d+`),
	// support for URI and WFN CPE 2.2 and 2.3 bindings
	CPE: regexp.MustCompile(`(?i)cpe(:2[.]3)?:[/]?[aoh*\-](:[?*]?([a-z0-9\-._]|([\\][\\?*!"#$%&'()+,/:;<=>@[\]^{|}~])|[%~])*[?*\-]?){0,5}(:([a-z]{2,3}(-([a-z]{2}|[0-9]{3}))?)|[*\-])?(:[?*]?([a-z0-9\-._]|([\\][\\?*!"#$%&'()+,/:;<=>@[\]^{|}~])|[%~])*[?*\-]?){0,5}`),
	// MITRE ATT&CK technique IDs (T#### or T####.###). Anchored + exact digit counts
	// to avoid matching arbitrary Tnnnn tokens.
	MITRE: regexp.MustCompile(`\bT\d{4}(?:\.\d{3})?\b`),
	// MAC addresses (colon- or dash-separated).
	MAC: regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`),
	// Monero addresses: start 4 (standard) or 8 (integrated/subaddress), base58,
	// 95 chars (or 106 for integrated).
	Monero: regexp.MustCompile(`\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?:[1-9A-HJ-NP-Za-km-z]{11})?\b`),
	// Ethereum addresses: 0x followed by 40 hex chars.
	Ethereum: regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`),
	// ssdeep fuzzy hashes: blocksize:hash:hash. Hash segments require >=6 base58/64
	// chars (well above IPv6's 4-hex-per-group max) so they can't match an IPv6 address.
	SSDeep: regexp.MustCompile(`\b\d+:[A-Za-z0-9/+]{6,}:[A-Za-z0-9/+]{6,}`),
}
