package fuzzer

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// A PayloadSource is a compact, server-resolved description of a payload list:
// a named built-in list or a parametric generator. It exists so the UI can send
// a tiny spec (a numeric range, a list id) instead of materializing and shipping
// millions of lines inline. Manual paste and file uploads never become a source —
// they stay inline []string on Config.Wordlist/Wordlists.
//
// It is one flat struct with a Kind discriminator, like Matcher/Filter; only the
// fields a kind names are read. Count reports the resolved length without
// allocating, so a caller can reject an oversized spec before Resolve builds it.
type PayloadSource struct {
	Kind SourceKind `json:"kind"`

	// builtin
	List string `json:"list,omitempty"`

	// numbers
	NumberMode string `json:"numberMode,omitempty"` // "range" (default) | "digits"
	Min        int64  `json:"min,omitempty"`
	Max        int64  `json:"max,omitempty"`
	Step       int64  `json:"step,omitempty"`
	MinDigits  int    `json:"minDigits,omitempty"`
	MaxDigits  int    `json:"maxDigits,omitempty"`
	Pad        int    `json:"pad,omitempty"`
	Hex        bool   `json:"hex,omitempty"`
	Upper      bool   `json:"upper,omitempty"`
	Prefix     string `json:"prefix,omitempty"`
	Suffix     string `json:"suffix,omitempty"`

	// chars (charset x length) and lengths (repeated-char ramp, reuses MinLen/MaxLen/Step)
	Charset string `json:"charset,omitempty"`
	MinLen  int    `json:"minLen,omitempty"`
	MaxLen  int    `json:"maxLen,omitempty"`
	Char    string `json:"char,omitempty"` // lengths: the repeated unit, default "A"

	// dates
	DateStart string `json:"dateStart,omitempty"` // YYYY-MM-DD
	DateEnd   string `json:"dateEnd,omitempty"`
	DateFmt   string `json:"dateFmt,omitempty"` // Go reference layout, default "2006-01-02"
	DateStep  int    `json:"dateStep,omitempty"` // days, default 1
}

// SourceKind names the shape of a PayloadSource.
type SourceKind string

const (
	SourceBuiltin SourceKind = "builtin"
	SourceNumbers SourceKind = "numbers"
	SourceChars   SourceKind = "chars"
	SourceLengths SourceKind = "lengths"
	SourceDates   SourceKind = "dates"
)

// MaxGeneratedPayloads caps the length of a single resolved source. It matches
// the yolo product ceiling in handleFuzzerStart, so a generated position and a
// cartesian run answer to the same order of magnitude.
const MaxGeneratedPayloads = 10_000_000

const defaultDateLayout = "2006-01-02"

// Count returns how many payloads the source resolves to, without allocating
// them, and validates the spec. A caller rejects the source when this exceeds
// its budget rather than letting Resolve allocate it.
func (s PayloadSource) Count() (int, error) {
	switch s.Kind {
	case SourceBuiltin:
		vals, ok := LookupBuiltin(s.List)
		if !ok {
			return 0, fmt.Errorf("unknown built-in list %q", s.List)
		}
		return len(vals), nil
	case SourceNumbers:
		return s.numberCount()
	case SourceChars:
		return s.charsCount()
	case SourceLengths:
		n, _, err := s.lengthsBounds()
		return n, err
	case SourceDates:
		n, _, _, err := s.datesBounds()
		return n, err
	default:
		return 0, fmt.Errorf("unknown source kind %q", s.Kind)
	}
}

// Resolve materializes the source into a payload list, refusing a spec whose
// Count exceeds limit.
func (s PayloadSource) Resolve(limit int) ([]string, error) {
	n, err := s.Count()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, fmt.Errorf("source produces no payloads")
	}
	if n > limit {
		return nil, fmt.Errorf("source would generate %d payloads (max %d)", n, limit)
	}
	switch s.Kind {
	case SourceBuiltin:
		vals, _ := LookupBuiltin(s.List)
		out := make([]string, len(vals))
		copy(out, vals)
		return out, nil
	case SourceNumbers:
		return s.resolveNumbers(n)
	case SourceChars:
		return s.resolveChars(n)
	case SourceLengths:
		return s.resolveLengths()
	case SourceDates:
		return s.resolveDates()
	default:
		return nil, fmt.Errorf("unknown source kind %q", s.Kind)
	}
}

// --- numbers ---

func (s PayloadSource) numberCount() (int, error) {
	if s.NumberMode == "digits" {
		return s.digitsCount()
	}
	step := s.Step
	if step == 0 {
		step = 1
	}
	if step < 0 {
		return 0, fmt.Errorf("numbers: step must be positive")
	}
	if s.Max < s.Min {
		return 0, fmt.Errorf("numbers: max must be >= min")
	}
	return int((s.Max-s.Min)/step) + 1, nil
}

func (s PayloadSource) resolveNumbers(n int) ([]string, error) {
	if s.NumberMode == "digits" {
		return s.resolveDigits()
	}
	step := s.Step
	if step == 0 {
		step = 1
	}
	out := make([]string, 0, n)
	for v := s.Min; v <= s.Max; v += step {
		out = append(out, s.formatNumber(v))
	}
	return out, nil
}

func (s PayloadSource) formatNumber(v int64) string {
	var body string
	if s.Hex {
		body = strconv.FormatInt(v, 16)
		if s.Upper {
			body = strings.ToUpper(body)
		}
	} else {
		body = strconv.FormatInt(v, 10)
	}
	if s.Pad > len(body) {
		body = strings.Repeat("0", s.Pad-len(body)) + body
	}
	return s.Prefix + body + s.Suffix
}

// digits mode enumerates every number of each width w in [MinDigits, MaxDigits]
// as a zero-padded run 0..10^w-1 — so "4 digits" is 0000..9999, the PIN/ID brute
// pattern. Each width is fully enumerated with its own padding.
func (s PayloadSource) digitsCount() (int, error) {
	if s.MinDigits < 1 || s.MaxDigits < s.MinDigits {
		return 0, fmt.Errorf("numbers: require 1 <= minDigits <= maxDigits")
	}
	if s.MaxDigits > 18 {
		return 0, fmt.Errorf("numbers: maxDigits too large")
	}
	total := 0
	for w := s.MinDigits; w <= s.MaxDigits; w++ {
		pow := 1
		for i := 0; i < w; i++ {
			pow *= 10
			if pow > MaxGeneratedPayloads {
				return pow, nil // caller rejects on the cap; stop before overflow
			}
		}
		total += pow
		if total > MaxGeneratedPayloads {
			return total, nil
		}
	}
	return total, nil
}

func (s PayloadSource) resolveDigits() ([]string, error) {
	n, err := s.digitsCount()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, n)
	for w := s.MinDigits; w <= s.MaxDigits; w++ {
		hi := int64(1)
		for i := 0; i < w; i++ {
			hi *= 10
		}
		for v := int64(0); v < hi; v++ {
			body := strconv.FormatInt(v, 10)
			if w > len(body) {
				body = strings.Repeat("0", w-len(body)) + body
			}
			out = append(out, s.Prefix+body+s.Suffix)
		}
	}
	return out, nil
}

// --- chars (charset x length) ---

func (s PayloadSource) charsCount() (int, error) {
	runes := []rune(s.Charset)
	if len(runes) == 0 {
		return 0, fmt.Errorf("chars: charset is empty")
	}
	if s.MinLen < 1 || s.MaxLen < s.MinLen {
		return 0, fmt.Errorf("chars: require 1 <= minLen <= maxLen")
	}
	total := 0
	for l := s.MinLen; l <= s.MaxLen; l++ {
		combos := 1
		for i := 0; i < l; i++ {
			combos *= len(runes)
			if combos > MaxGeneratedPayloads {
				return combos, nil
			}
		}
		total += combos
		if total > MaxGeneratedPayloads {
			return total, nil
		}
	}
	return total, nil
}

func (s PayloadSource) resolveChars(n int) ([]string, error) {
	runes := []rune(s.Charset)
	out := make([]string, 0, n)
	for l := s.MinLen; l <= s.MaxLen; l++ {
		idx := make([]int, l) // odometer over charset, position 0 is least significant
		for {
			var b strings.Builder
			for i := l - 1; i >= 0; i-- {
				b.WriteRune(runes[idx[i]])
			}
			out = append(out, b.String())
			// increment the odometer
			pos := 0
			for pos < l {
				idx[pos]++
				if idx[pos] < len(runes) {
					break
				}
				idx[pos] = 0
				pos++
			}
			if pos == l {
				break
			}
		}
	}
	return out, nil
}

// --- lengths (repeated-char ramp) ---

func (s PayloadSource) lengthsBounds() (count, step int, err error) {
	step = int(s.Step)
	if step == 0 {
		step = 1
	}
	if step < 0 {
		return 0, 0, fmt.Errorf("lengths: step must be positive")
	}
	if s.MinLen < 1 || s.MaxLen < s.MinLen {
		return 0, 0, fmt.Errorf("lengths: require 1 <= minLen <= maxLen")
	}
	return (s.MaxLen-s.MinLen)/step + 1, step, nil
}

func (s PayloadSource) resolveLengths() ([]string, error) {
	n, step, err := s.lengthsBounds()
	if err != nil {
		return nil, err
	}
	unit := s.Char
	if unit == "" {
		unit = "A"
	}
	out := make([]string, 0, n)
	for l := s.MinLen; l <= s.MaxLen; l += step {
		out = append(out, strings.Repeat(unit, l))
	}
	return out, nil
}

// --- dates ---

func (s PayloadSource) datesBounds() (count int, start time.Time, step int, err error) {
	start, err = time.Parse(defaultDateLayout, s.DateStart)
	if err != nil {
		return 0, time.Time{}, 0, fmt.Errorf("dates: invalid dateStart (want YYYY-MM-DD)")
	}
	end, err := time.Parse(defaultDateLayout, s.DateEnd)
	if err != nil {
		return 0, time.Time{}, 0, fmt.Errorf("dates: invalid dateEnd (want YYYY-MM-DD)")
	}
	if end.Before(start) {
		return 0, time.Time{}, 0, fmt.Errorf("dates: dateEnd must be >= dateStart")
	}
	step = s.DateStep
	if step == 0 {
		step = 1
	}
	if step < 0 {
		return 0, time.Time{}, 0, fmt.Errorf("dates: step must be positive")
	}
	days := int(end.Sub(start).Hours()/24) + 1
	return (days-1)/step + 1, start, step, nil
}

func (s PayloadSource) resolveDates() ([]string, error) {
	n, start, step, err := s.datesBounds()
	if err != nil {
		return nil, err
	}
	layout := s.DateFmt
	if layout == "" {
		layout = defaultDateLayout
	}
	end, _ := time.Parse(defaultDateLayout, s.DateEnd)
	out := make([]string, 0, n)
	for d := start; !d.After(end); d = d.AddDate(0, 0, step) {
		out = append(out, d.Format(layout))
	}
	return out, nil
}
