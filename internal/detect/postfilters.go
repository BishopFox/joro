package detect

import (
	"encoding/base64"
	"strings"
	"unicode"
)

// filterContext is everything a post-filter may inspect: the captured group, its
// position inside the scanned buffer, that buffer, and the parsed message.
// Position and buffer support filters that examine the match's neighbours, such
// as separating the IP 10.1.2.3 from the version string 1.10.1.2.3.
type filterContext struct {
	Match  string
	Offset int
	Hay    []byte
	Msg    *Message
}

// postFilter reports whether a captured group survives. Returning false drops
// the match silently, as if the pattern had not matched. RE2 has no lookahead or
// lookbehind, so negative conditions are expressed here as Go code.
type postFilter func(filterContext) bool

// postFilterRegistry maps the names used in Rule.PostFilters to their
// implementations. Operators may reference these by name but cannot add new ones.
var postFilterRegistry = map[string]postFilter{
	"luhn":             filterLuhn,
	"iban97":           filterIBAN97,
	"ssn":              filterSSN,
	"mod11nhs":         filterNHS,
	"cpf":              filterCPF,
	"verhoeff":         filterVerhoeff,
	"rutMod11":         filterRUT,
	"denylist":         filterDenylist,
	"notVersionString": filterNotVersionString,
	"notHTML":          filterNotHTML,
	"basicCreds":       filterBasicCreds,
	"jwtStructure":     filterJWTStructure,
	"notHashLike":      filterNotHashLike,
}

// resolvePostFilters looks up filter names, skipping unknown ones so a rule from
// a newer build degrades to a looser check rather than failing.
func resolvePostFilters(names []string) []postFilter {
	if len(names) == 0 {
		return nil
	}
	out := make([]postFilter, 0, len(names))
	for _, n := range names {
		if f, ok := postFilterRegistry[n]; ok {
			out = append(out, f)
		}
	}
	return out
}

// PostFilterNames returns the registered post-filter names, for API validation
// of operator-supplied rules.
func PostFilterNames() []string {
	out := make([]string, 0, len(postFilterRegistry))
	for n := range postFilterRegistry {
		out = append(out, n)
	}
	return out
}

// digitsOnly strips every non-digit byte.
func digitsOnly(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// filterDenylist rejects template, sample, and masked values.
func filterDenylist(ctx filterContext) bool {
	return !isPlaceholder(ctx.Match)
}

// knownTestPANs are the card numbers published in payment-gateway documentation.
// All pass Luhn, so they are rejected by value.
var knownTestPANs = map[string]struct{}{
	"4111111111111111": {}, "4012888888881881": {}, "4222222222222": {},
	"4242424242424242": {}, "4000000000000002": {}, "4000000000000069": {},
	"4000000000000119": {}, "4000000000009995": {}, "4000056655665556": {},
	"5555555555554444": {}, "5105105105105100": {}, "5200828282828210": {},
	"5555555555555555": {}, "2223003122003222": {},
	"378282246310005": {}, "371449635398431": {}, "378734493671000": {},
	"340000000000009": {},
	"30569309025904":  {}, "38520000023237": {}, "36227206271667": {},
	"6011111111111117": {}, "6011000990139424": {}, "6011000000000004": {},
	"3530111333300000": {}, "3566002020360505": {},
	"6200000000000005": {}, "6205500000000000004": {},
}

// panLengthValid checks the digit count against the issuer identified by the
// leading digits.
func panLengthValid(d string) bool {
	n := len(d)
	switch {
	case strings.HasPrefix(d, "34"), strings.HasPrefix(d, "37"):
		return n == 15 // American Express
	case strings.HasPrefix(d, "36"), strings.HasPrefix(d, "38"),
		strings.HasPrefix(d, "300"), strings.HasPrefix(d, "301"),
		strings.HasPrefix(d, "302"), strings.HasPrefix(d, "303"),
		strings.HasPrefix(d, "304"), strings.HasPrefix(d, "305"):
		return n == 14 // Diners Club
	case strings.HasPrefix(d, "62"):
		return n >= 16 && n <= 19 // UnionPay
	case d[0] == '4':
		return n == 16 || n == 13 // Visa (13 is legacy but still issued historically)
	default:
		return n == 16
	}
}

// luhnValid runs the Luhn checksum.
func luhnValid(d string) bool {
	if len(d) < 12 {
		return false
	}
	sum := 0
	double := false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

// filterLuhn validates a candidate card number with the Luhn checksum, a brand
// length check, and the test-PAN denylist.
func filterLuhn(ctx filterContext) bool {
	d := digitsOnly(ctx.Match)
	if d == "" {
		return false
	}
	if _, isTest := knownTestPANs[d]; isTest {
		return false
	}
	if isRepeatedRune(d) {
		return false
	}
	return panLengthValid(d) && luhnValid(d)
}

// knownFakeSSNs are the placeholder social security numbers used in adverts,
// training material, and test fixtures.
var knownFakeSSNs = map[string]struct{}{
	"078051120": {}, // the 1938 wallet-insert number
	"111111111": {}, "123456789": {}, "219099999": {},
	"222222222": {}, "333333333": {}, "444444444": {},
	"555555555": {}, "666666666": {}, "777777777": {},
	"888888888": {}, "987654320": {}, "987654321": {},
	"987654322": {}, "987654323": {}, "987654324": {},
	"987654325": {}, "987654326": {}, "987654327": {},
	"987654328": {}, "987654329": {},
}

// filterSSN applies the Social Security Administration's structural rules (area
// 000, 666, and 900-999, group 00, and serial 0000 are never assigned) plus the
// knownFakeSSNs list.
func filterSSN(ctx filterContext) bool {
	d := digitsOnly(ctx.Match)
	if len(d) != 9 {
		return false
	}
	if _, fake := knownFakeSSNs[d]; fake {
		return false
	}
	area := d[0:3]
	group := d[3:5]
	serial := d[5:9]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}

// ibanLengths is the official IBAN length per country, checked before the mod-97
// arithmetic.
var ibanLengths = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
	"BG": 22, "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28,
	"CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24,
	"FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18,
	"GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23,
	"IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32,
	"LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24,
	"ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15,
	"PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
	"SA": 24, "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25,
	"SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24,
	"XK": 20,
}

// filterIBAN97 runs the ISO 13616 mod-97 check.
func filterIBAN97(ctx filterContext) bool {
	s := strings.ToUpper(strings.ReplaceAll(ctx.Match, " ", ""))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	want, ok := ibanLengths[s[0:2]]
	if !ok || len(s) != want {
		return false
	}
	// Move the first four characters to the end, then treat letters as numbers
	// (A=10 ... Z=35) and take the whole value mod 97 incrementally.
	rearranged := s[4:] + s[0:4]
	rem := 0
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		switch {
		case c >= '0' && c <= '9':
			rem = (rem*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			v := int(c-'A') + 10
			rem = (rem*100 + v) % 97
		default:
			return false
		}
	}
	return rem == 1
}

// filterNHS validates an NHS number's mod-11 check digit.
func filterNHS(ctx filterContext) bool {
	d := digitsOnly(ctx.Match)
	if len(d) != 10 || isRepeatedRune(d) {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(d[i]-'0') * (10 - i)
	}
	check := 11 - (sum % 11)
	switch check {
	case 11:
		check = 0
	case 10:
		return false // 10 is not a valid check digit; the number is invalid
	}
	return check == int(d[9]-'0')
}

// filterCPF validates the two check digits of a Brazilian CPF.
func filterCPF(ctx filterContext) bool {
	d := digitsOnly(ctx.Match)
	if len(d) != 11 || isRepeatedRune(d) {
		return false
	}
	check := func(upTo int) int {
		sum := 0
		weight := upTo + 1
		for i := 0; i < upTo; i++ {
			sum += int(d[i]-'0') * weight
			weight--
		}
		r := (sum * 10) % 11
		if r == 10 {
			return 0
		}
		return r
	}
	return check(9) == int(d[9]-'0') && check(10) == int(d[10]-'0')
}

// verhoeffD, verhoeffP, and verhoeffInv are the Verhoeff algorithm tables used
// by India's Aadhaar number.
var (
	verhoeffD = [10][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
		{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
		{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
		{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
		{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
		{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
		{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
		{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}
	verhoeffP = [8][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
		{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
		{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
		{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
		{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
		{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
	}
)

// filterVerhoeff validates a 12-digit Aadhaar number's Verhoeff check digit.
func filterVerhoeff(ctx filterContext) bool {
	d := digitsOnly(ctx.Match)
	if len(d) != 12 || isRepeatedRune(d) {
		return false
	}
	// Aadhaar numbers never start with 0 or 1.
	if d[0] == '0' || d[0] == '1' {
		return false
	}
	c := 0
	for i := 0; i < len(d); i++ {
		digit := int(d[len(d)-1-i] - '0')
		c = verhoeffD[c][verhoeffP[i%8][digit]]
	}
	return c == 0
}

// filterRUT validates a Chilean RUT (Rol Único Tributario) by its mod-11 check
// digit. The body is 7-8 digits and the check digit is 0-9 or K: weight the body
// right-to-left by 2,3,4,5,6,7 cycling; the digit is 11-(sum mod 11), with 11
// rendered as 0 and 10 as K.
func filterRUT(ctx filterContext) bool {
	v := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(ctx.Match), ".", ""))
	dash := strings.LastIndexByte(v, '-')
	if dash < 0 || dash != len(v)-2 {
		return false
	}
	body, given := v[:dash], v[dash+1]
	if len(body) < 7 || len(body) > 8 {
		return false
	}
	for i := 0; i < len(body); i++ {
		if body[i] < '0' || body[i] > '9' {
			return false
		}
	}
	// 11.111.111-1 satisfies the checksum but is the standard Chilean placeholder.
	if isRepeatedRune(body) {
		return false
	}

	sum, weight := 0, 2
	for i := len(body) - 1; i >= 0; i-- {
		sum += int(body[i]-'0') * weight
		if weight == 7 {
			weight = 2
		} else {
			weight++
		}
	}
	var want byte
	switch r := 11 - (sum % 11); r {
	case 11:
		want = '0'
	case 10:
		want = 'K'
	default:
		want = byte('0' + r)
	}
	return given == want
}

// versionContextWords indicate the surrounding text is describing a version
// number rather than an address.
var versionContextWords = []string{
	"version", "release", "build", "semver", "changelog", "revision",
	"v.", "sdk", "runtime", "engine", "schema", "migrat",
}

// filterNotVersionString rejects private-range IP matches that are part of a
// longer dotted-numeric token or sit in version-string context, e.g. "1.10.0.1".
func filterNotVersionString(ctx filterContext) bool {
	// A digit or dot immediately before the match means the match is a suffix of
	// a longer numeric token (1.10.1.2.3), not a standalone address.
	if ctx.Offset > 0 && ctx.Offset <= len(ctx.Hay) {
		prev := ctx.Hay[ctx.Offset-1]
		if prev == '.' || (prev >= '0' && prev <= '9') {
			return false
		}
	}
	// A dot followed by a digit immediately after means the same on the right.
	end := ctx.Offset + len(ctx.Match)
	if end+1 < len(ctx.Hay) && ctx.Hay[end] == '.' &&
		ctx.Hay[end+1] >= '0' && ctx.Hay[end+1] <= '9' {
		return false
	}
	// Look at a small window of surrounding text for version vocabulary.
	lo := ctx.Offset - 40
	if lo < 0 {
		lo = 0
	}
	hi := end + 40
	if hi > len(ctx.Hay) {
		hi = len(ctx.Hay)
	}
	if lo < hi {
		window := strings.ToLower(string(ctx.Hay[lo:hi]))
		for _, w := range versionContextWords {
			if strings.Contains(window, w) {
				return false
			}
		}
	}
	return true
}

// filterNotHTML rejects matches in an HTML response. Requesting /.env from a
// single-page app returns index.html with status 200, which a URL-only rule
// would otherwise report as a config-file exposure.
func filterNotHTML(ctx filterContext) bool {
	if ctx.Msg == nil {
		return true
	}
	if strings.Contains(strings.ToLower(ctx.Msg.ContentType), "text/html") {
		return false
	}
	head := ctx.Msg.RespBody
	if len(head) > 512 {
		head = head[:512]
	}
	lower := strings.ToLower(strings.TrimSpace(string(head)))
	if strings.HasPrefix(lower, "<!doctype html") || strings.HasPrefix(lower, "<html") {
		return false
	}
	return true
}

// filterBasicCreds validates that an Authorization: Basic payload base64-decodes
// to a credential pair.
func filterBasicCreds(ctx filterContext) bool {
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ctx.Match))
	if err != nil {
		return false
	}
	s := string(dec)
	if !strings.Contains(s, ":") {
		return false
	}
	for _, r := range s {
		if r > unicode.MaxASCII || (r < 0x20 && r != '\t') || r == 0x7f {
			return false
		}
	}
	return true
}

// filterJWTStructure requires that the first segment base64url-decodes to
// something that looks like a JOSE header, which rules out arbitrary
// dot-separated base64 tokens.
func filterJWTStructure(ctx filterContext) bool {
	parts := strings.Split(ctx.Match, ".")
	if len(parts) != 3 {
		return false
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	s := string(hdr)
	return strings.Contains(s, "\"alg\"") || strings.Contains(s, "'alg'")
}

// filterNotHashLike rejects bare 32/40/64-character hex strings, which are MD5,
// SHA-1, and SHA-256 digests rather than secrets.
func filterNotHashLike(ctx filterContext) bool {
	v := strings.TrimSpace(ctx.Match)
	switch len(v) {
	case 32, 40, 64:
	default:
		return true
	}
	for i := 0; i < len(v); i++ {
		c := v[i] | 0x20 // fold case
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return true
		}
	}
	return false
}
