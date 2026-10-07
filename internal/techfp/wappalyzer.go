// Package techfp is Joro's passive technology fingerprinter. Like detect, echo
// and anomaly, it only ever reads captured traffic — it never originates a
// request. It pulls responses from the proxy store, matches them against the
// embedded Wappalyzer database, and tags each host with the technologies it
// serves. The active-scan signature rule reads those tags to run only the checks
// that match a host's stack.
//
// # Only what a response reveals
//
// The Wappalyzer database also carries js/ and dom/ rules that require executing
// a page in a browser. This engine evaluates only the HTTP-observable keys —
// headers, cookies, html, scriptSrc, meta and url — and ignores js/dom at load.
// Coverage is therefore honestly narrower than a browser-driven scan rather than
// silently wrong: a tech only detectable by running its JavaScript is simply not
// reported.
//
// # Fail-open, because it is advisory
//
// Unlike a vulnerability finding, a technology tag is advisory: a wrong tag only
// mis-gates a later scan. So a pattern that will not compile under RE2 is dropped
// (not an error), and gating fails open on an unknown version.
package techfp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Detection is one technology matched in a single response.
type Detection struct {
	Name       string
	Version    string
	Categories []string
	Confidence int
}

// Input is the HTTP-observable surface of one response.
type Input struct {
	Header http.Header
	URL    string
	Body   []byte // decoded body, already size-capped; only read when IsHTML
	IsHTML bool
}

// cpattern is a compiled Wappalyzer pattern. A nil re means presence-only (an
// empty pattern string, used by cookie rules that match on a cookie's existence).
type cpattern struct {
	re       *regexp.Regexp
	verGroup int // capture group holding the version, 0 for none
	conf     int // confidence weight, default 100
}

// techDef is one technology's compiled rules.
type techDef struct {
	name      string
	cats      []string
	headers   map[string][]cpattern // canonical header name -> patterns
	cookies   map[string][]cpattern // lower cookie name -> patterns
	meta      map[string][]cpattern // lower meta name -> patterns
	html      []cpattern
	scriptSrc []cpattern
	url       []cpattern
	implies   []string
}

func (t *techDef) deep() bool {
	return len(t.html) > 0 || len(t.scriptSrc) > 0 || len(t.meta) > 0
}

// Wappalyzer is the compiled, queryable fingerprint database.
type Wappalyzer struct {
	byName map[string]*techDef
	// Field-partitioned views so a lookup touches only the techs that declare a
	// rule of that kind, not all ~7600.
	headerTechs []*techDef
	cookieTechs []*techDef
	urlTechs    []*techDef
	deepTechs   []*techDef
}

// Names returns every technology name in the database. tools/nucleigen uses it to
// map a nuclei template's tags to canonical technology names for RequiresTech.
func (w *Wappalyzer) Names() []string {
	out := make([]string, 0, len(w.byName))
	for name := range w.byName {
		out = append(out, name)
	}
	return out
}

// Stats reports how the database compiled, for a startup log line.
type Stats struct {
	Techs    int
	Patterns int
	Dropped  int // patterns rejected by RE2
}

// stringList unmarshals a JSON value that may be a string or an array of strings.
type stringList []string

func (s *stringList) UnmarshalJSON(b []byte) error {
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '[' {
		var a []string
		if err := json.Unmarshal(b, &a); err != nil {
			return err
		}
		*s = a
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	*s = []string{str}
	return nil
}

type rawApp struct {
	Cats      []int                 `json:"cats"`
	Headers   map[string]stringList `json:"headers"`
	Cookies   map[string]stringList `json:"cookies"`
	Meta      map[string]stringList `json:"meta"`
	HTML      stringList            `json:"html"`
	ScriptSrc stringList            `json:"scriptSrc"`
	URL       stringList            `json:"url"`
	Implies   stringList            `json:"implies"`
}

type rawCategory struct {
	Name string `json:"name"`
}

// LoadWappalyzer parses and compiles the embedded database. It is called once,
// from the engine's background loop, so the RE2 compilation cost stays off the
// server's boot path.
func LoadWappalyzer() (*Wappalyzer, Stats, error) {
	var fp struct {
		Apps map[string]rawApp `json:"apps"`
	}
	if err := json.Unmarshal(fingerprintsJSON, &fp); err != nil {
		return nil, Stats{}, fmt.Errorf("fingerprints: %w", err)
	}
	var cats map[string]rawCategory
	if err := json.Unmarshal(categoriesJSON, &cats); err != nil {
		return nil, Stats{}, fmt.Errorf("categories: %w", err)
	}

	w := &Wappalyzer{byName: make(map[string]*techDef, len(fp.Apps))}
	var st Stats
	for name, app := range fp.Apps {
		t := &techDef{name: name}
		for _, id := range app.Cats {
			if c, ok := cats[strconv.Itoa(id)]; ok && c.Name != "" {
				t.cats = append(t.cats, c.Name)
			}
		}
		t.headers = compileNamed(app.Headers, http.CanonicalHeaderKey, &st)
		t.cookies = compileNamed(app.Cookies, strings.ToLower, &st)
		t.meta = compileNamed(app.Meta, strings.ToLower, &st)
		t.html = compileList(app.HTML, &st)
		t.scriptSrc = compileList(app.ScriptSrc, &st)
		t.url = compileList(app.URL, &st)
		for _, imp := range app.Implies {
			if n := strings.TrimSpace(splitPattern(imp)[0]); n != "" {
				t.implies = append(t.implies, n)
			}
		}

		w.byName[name] = t
		st.Techs++
		if len(t.headers) > 0 {
			w.headerTechs = append(w.headerTechs, t)
		}
		if len(t.cookies) > 0 {
			w.cookieTechs = append(w.cookieTechs, t)
		}
		if len(t.url) > 0 {
			w.urlTechs = append(w.urlTechs, t)
		}
		if t.deep() {
			w.deepTechs = append(w.deepTechs, t)
		}
	}
	return w, st, nil
}

func compileNamed(in map[string]stringList, key func(string) string, st *Stats) map[string][]cpattern {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]cpattern, len(in))
	for name, pats := range in {
		var cps []cpattern
		for _, p := range pats {
			if cp, ok := compilePattern(p, st); ok {
				cps = append(cps, cp)
			}
		}
		// A named rule with only uncompilable patterns is still a presence check.
		if len(cps) == 0 {
			cps = []cpattern{{conf: 100}}
		}
		out[key(name)] = cps
	}
	return out
}

func compileList(in stringList, st *Stats) []cpattern {
	var out []cpattern
	for _, p := range in {
		if cp, ok := compilePattern(p, st); ok {
			out = append(out, cp)
		}
	}
	return out
}

// splitPattern splits a Wappalyzer pattern on its "\;" tag separator.
func splitPattern(p string) []string { return strings.Split(p, `\;`) }

// compilePattern parses one Wappalyzer pattern: the leading regex plus optional
// \;version: and \;confidence: tags. An empty regex compiles to a presence-only
// pattern; a regex RE2 rejects is dropped (counted in Stats.Dropped).
func compilePattern(raw string, st *Stats) (cpattern, bool) {
	st.Patterns++
	parts := splitPattern(raw)
	expr := parts[0]
	cp := cpattern{conf: 100}
	for _, tag := range parts[1:] {
		switch {
		case strings.HasPrefix(tag, "version:"):
			cp.verGroup = firstBackref(tag[len("version:"):])
		case strings.HasPrefix(tag, "confidence:"):
			if n, err := strconv.Atoi(strings.TrimSpace(tag[len("confidence:"):])); err == nil {
				cp.conf = n
			}
		}
	}
	if expr == "" {
		return cp, true
	}
	re, err := regexp.Compile("(?i)" + expr)
	if err != nil {
		st.Dropped++
		return cpattern{}, false
	}
	cp.re = re
	return cp, true
}

var backrefRe = regexp.MustCompile(`\\(\d+)`)

// firstBackref returns the first \N group index in a version spec, or 0. The
// ternary forms Wappalyzer sometimes uses (\1?\2:) degrade to their first group.
func firstBackref(spec string) int {
	m := backrefRe.FindStringSubmatch(spec)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// Fingerprint returns every technology the input reveals, with implied
// technologies resolved transitively.
func (w *Wappalyzer) Fingerprint(in Input) []Detection {
	hits := map[string]*Detection{}

	mark := func(t *techDef, cp cpattern, m []string) {
		d := hits[t.name]
		if d == nil {
			d = &Detection{Name: t.name, Categories: t.cats, Confidence: cp.conf}
			hits[t.name] = d
		}
		if cp.conf > d.Confidence {
			d.Confidence = cp.conf
		}
		if d.Version == "" && cp.verGroup > 0 && len(m) > cp.verGroup {
			d.Version = strings.TrimSpace(m[cp.verGroup])
		}
	}
	match := func(t *techDef, cps []cpattern, hay string) {
		for _, cp := range cps {
			if cp.re == nil {
				mark(t, cp, nil)
				continue
			}
			if m := cp.re.FindStringSubmatch(hay); m != nil {
				mark(t, cp, m)
			}
		}
	}

	if in.Header != nil {
		for _, t := range w.headerTechs {
			for name, cps := range t.headers {
				vals := in.Header.Values(name)
				if len(vals) == 0 {
					continue
				}
				match(t, cps, strings.Join(vals, ", "))
			}
		}
		if cookies := parseSetCookies(in.Header); len(cookies) > 0 {
			for _, t := range w.cookieTechs {
				for name, cps := range t.cookies {
					if v, ok := cookies[name]; ok {
						match(t, cps, v)
					}
				}
			}
		}
	}
	if in.URL != "" {
		for _, t := range w.urlTechs {
			match(t, t.url, in.URL)
		}
	}
	if in.IsHTML && len(in.Body) > 0 {
		body := string(in.Body)
		scripts := extractScriptSrcs(body)
		metas := extractMetas(body)
		for _, t := range w.deepTechs {
			match(t, t.html, body)
			for _, cp := range t.scriptSrc {
				for _, src := range scripts {
					if cp.re == nil {
						mark(t, cp, nil)
						break
					}
					if m := cp.re.FindStringSubmatch(src); m != nil {
						mark(t, cp, m)
						break
					}
				}
			}
			for name, cps := range t.meta {
				if v, ok := metas[name]; ok {
					match(t, cps, v)
				}
			}
		}
	}

	w.resolveImplies(hits)

	out := make([]Detection, 0, len(hits))
	for _, d := range hits {
		out = append(out, *d)
	}
	return out
}

// resolveImplies adds implied technologies transitively. Implied techs are given
// a reduced confidence so a directly-observed tech always outranks an inferred one.
func (w *Wappalyzer) resolveImplies(hits map[string]*Detection) {
	queue := make([]string, 0, len(hits))
	for name := range hits {
		queue = append(queue, name)
	}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		t := w.byName[name]
		if t == nil {
			continue
		}
		for _, imp := range t.implies {
			if _, seen := hits[imp]; seen {
				continue
			}
			it := w.byName[imp]
			cats := []string(nil)
			if it != nil {
				cats = it.cats
			}
			hits[imp] = &Detection{Name: imp, Categories: cats, Confidence: 50}
			queue = append(queue, imp)
		}
	}
}

// parseSetCookies maps lower-cased cookie names to their values from Set-Cookie.
func parseSetCookies(h http.Header) map[string]string {
	vals := h.Values("Set-Cookie")
	if len(vals) == 0 {
		return nil
	}
	out := make(map[string]string, len(vals))
	for _, c := range vals {
		pair := c
		if i := strings.IndexByte(pair, ';'); i >= 0 {
			pair = pair[:i]
		}
		name, value, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
	}
	return out
}

// HTML attribute extractors, hand-rolled and lenient for the same reason echo's
// context scanner is: these run over adversarial markup and x/net/html's strict
// tokenizer would reject what a browser tolerates.
var (
	scriptSrcRe = regexp.MustCompile(`(?i)<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)`)
	metaTagRe   = regexp.MustCompile(`(?i)<meta\b[^>]*>`)
	metaNameRe  = regexp.MustCompile(`(?i)\b(?:name|property|http-equiv)\s*=\s*["']?([^"'\s>]+)`)
	metaContRe  = regexp.MustCompile(`(?i)\bcontent\s*=\s*["']?([^"'>]*)`)
)

func extractScriptSrcs(body string) []string {
	ms := scriptSrcRe.FindAllStringSubmatch(body, -1)
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m[1])
	}
	return out
}

func extractMetas(body string) map[string]string {
	tags := metaTagRe.FindAllString(body, -1)
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		name := metaNameRe.FindStringSubmatch(tag)
		cont := metaContRe.FindStringSubmatch(tag)
		if name == nil || cont == nil {
			continue
		}
		out[strings.ToLower(name[1])] = cont[1]
	}
	return out
}
