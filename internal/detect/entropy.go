package detect

import (
	"math"
	"strings"
)

// ShannonEntropy returns the Shannon entropy of s in bits per character. Used to
// validate a value a pattern already matched, never as a detector on its own.
// For calibration: random base64 scores around 6.0, random hex around 4.0, and
// English prose 4.0 to 4.5.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// placeholderExact are values appearing verbatim in sample code, templates, and
// documentation.
var placeholderExact = map[string]struct{}{
	"":                    {},
	"null":                {},
	"nil":                 {},
	"none":                {},
	"undefined":           {},
	"true":                {},
	"false":               {},
	"changeme":            {},
	"change_me":           {},
	"example":             {},
	"test":                {},
	"testing":             {},
	"password":            {},
	"passwd":              {},
	"secret":              {},
	"token":               {},
	"apikey":              {},
	"api_key":             {},
	"your_api_key":        {},
	"your_api_key_here":   {},
	"your-api-key":        {},
	"your_secret":         {},
	"your_secret_here":    {},
	"your_token_here":     {},
	"my_api_key":          {},
	"replace_me":          {},
	"replaceme":           {},
	"placeholder":         {},
	"redacted":            {},
	"insert_key_here":     {},
	"todo":                {},
	"fixme":               {},
	"dummy":               {},
	"sample":              {},
	"foobar":              {},
	"lorem":               {},
	"abc123":              {},
	"123456":              {},
	"12345678":            {},
	"password123":         {},
	"admin":               {},
	"root":                {},
	"unset":               {},
	"empty":               {},
	"n/a":                 {},
	"na":                  {},
	"xxxxxxxx":            {},
	"deadbeef":            {},
	"00000000":            {},
	"sk_test_key":         {},
	"development":         {},
	"production":          {},
	"localhost":           {},
	"do_not_use":          {},
	"not_a_real_key":      {},
	"enter_your_key_here": {},
}

// placeholderSubstrings mark a value as a template rather than a live secret.
var placeholderSubstrings = []string{
	"your_", "your-", "yourapi", "youraccount",
	"example.com", "example.org", "example_",
	"replace_", "replaceme", "insert_", "enter_",
	"changeme", "change_me", "placeholder", "redacted",
	"dummy", "notreal", "not_real", "fake_", "_fake",
	"xxxxx", "aaaaa", "zzzzz", "12345678",
	"todo", "fixme", "tbd",
	"my_secret", "my_token", "my_api",
	"sample_", "_sample", "demo_", "_demo",
	"test_key", "testkey", "test_token", "test_secret",
	"lorem", "ipsum",
}

// isPlaceholder reports whether v is a template, sample, or documentation value
// rather than a plausible live secret. Runs before the entropy gate;
// "YOUR_API_KEY_HERE" and "${process.env.SECRET}" both score respectably.
func isPlaceholder(v string) bool {
	t := strings.TrimSpace(v)
	if t == "" {
		return true
	}
	lower := strings.ToLower(t)
	if _, ok := placeholderExact[lower]; ok {
		return true
	}

	// Template interpolation and shell/env indirection: the literal value is a
	// reference, not the secret.
	switch {
	case strings.HasPrefix(t, "${"), strings.HasPrefix(t, "{{"),
		strings.HasPrefix(t, "<%"), strings.HasPrefix(t, "%("),
		strings.HasPrefix(t, "$("), strings.HasPrefix(t, "#{"):
		return true
	case strings.HasPrefix(t, "<") && strings.HasSuffix(t, ">"):
		// <your-key-here>, <REDACTED>
		return true
	case strings.HasPrefix(lower, "process.env"), strings.HasPrefix(lower, "os.environ"),
		strings.HasPrefix(lower, "env."), strings.HasPrefix(lower, "config."),
		strings.HasPrefix(lower, "import.meta.env"):
		return true
	}

	// Format specifiers left in a template string.
	if t == "%s" || t == "%d" || t == "%v" || t == "*" {
		return true
	}

	for _, sub := range placeholderSubstrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}

	// A single repeated character, or a masked value such as "••••" / "****".
	if isRepeatedRune(t) {
		return true
	}

	return false
}

// isRepeatedRune reports whether s consists of one rune repeated, which covers
// masked values ("****", "••••") and filler ("aaaaaaaa", "00000000").
func isRepeatedRune(s string) bool {
	var first rune
	set := false
	for _, r := range s {
		if !set {
			first, set = r, true
			continue
		}
		if r != first {
			return false
		}
	}
	return set
}
