// Command nucleigen is Joro's design-time converter: it reads a reviewed
// nuclei-templates checkout and emits the normalized signature dataset that
// internal/activescan/templatesig embeds. It is a developer tool and is never
// imported by the server — the server ships the generated JSON, not a YAML parser.
//
// It is fail-closed: a template is converted only when its whole logic fits the
// supported HTTP matcher subset (a single http request block; method+path probes;
// status/word/regex/size matchers with and/or and negation; RE2-compatible
// regexes). Everything else is dropped and tallied in a skip census — the census
// being the roadmap for what to support next.
//
// Usage:
//
//	go run ./tools/nucleigen -templates /path/to/nuclei-templates -out internal/activescan/templatesig/signatures.json
//
// By default it reads only the http/ tree and excludes http/technologies/, whose
// detection job belongs to the passive fingerprinter.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BishopFox/joro/internal/activescan/templatesig"
	"github.com/BishopFox/joro/internal/techfp"
	"gopkg.in/yaml.v3"
)

func main() {
	var (
		templatesDir = flag.String("templates", "", "path to a nuclei-templates checkout")
		outPath      = flag.String("out", "internal/activescan/templatesig/signatures.json", "output dataset path")
		subdir       = flag.String("subdir", "http", "subtree under the checkout to walk")
	)
	flag.Parse()
	if *templatesDir == "" {
		fmt.Fprintln(os.Stderr, "nucleigen: -templates is required")
		os.Exit(2)
	}

	techNames, err := loadTechNames()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nucleigen: load tech names: %v\n", err)
		os.Exit(1)
	}

	root := filepath.Join(*templatesDir, *subdir)
	census := map[string]int{}
	var sigs []templatesig.Signature
	seen := map[string]bool{}

	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		// Detection-only templates are the fingerprinter's job, not a vuln signature.
		if strings.Contains(filepath.ToSlash(path), "/technologies/") {
			census["excluded:technologies"]++
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			census["read-error"]++
			return nil
		}
		rel, _ := filepath.Rel(*templatesDir, path)
		sig, reason := convert(data, rel, techNames)
		if reason != "" {
			census["skip:"+reason]++
			return nil
		}
		if seen[sig.ID] {
			census["skip:duplicate-id"]++
			return nil
		}
		seen[sig.ID] = true
		sigs = append(sigs, *sig)
		census["converted"]++
		return nil
	})
	if walkErr != nil {
		fmt.Fprintf(os.Stderr, "nucleigen: walk: %v\n", walkErr)
		os.Exit(1)
	}

	sort.Slice(sigs, func(i, j int) bool { return sigs[i].ID < sigs[j].ID })
	out, _ := json.MarshalIndent(sigs, "", "  ")
	if err := os.WriteFile(*outPath, append(out, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "nucleigen: write: %v\n", err)
		os.Exit(1)
	}

	printCensus(census, *outPath)
}

// loadTechNames returns a lower-cased set of canonical Wappalyzer technology names.
func loadTechNames() (map[string]string, error) {
	w, _, err := techfp.LoadWappalyzer()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, n := range w.Names() {
		out[strings.ToLower(n)] = n
	}
	return out, nil
}

// --- nuclei template shapes (only the fields the subset reads) ---

type nTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string     `yaml:"name"`
		Severity    string     `yaml:"severity"`
		Description string     `yaml:"description"`
		Reference   stringList `yaml:"reference"`
		Tags        stringList `yaml:"tags"`
		Metadata    yaml.Node  `yaml:"metadata"`
		Remediation string     `yaml:"remediation"`
	} `yaml:"info"`
	HTTP     []nRequest `yaml:"http"`
	Requests []nRequest `yaml:"requests"` // legacy key for http
	// Presence of any of these marks an unsupported protocol/feature.
	Headless   yaml.Node `yaml:"headless"`
	Network    yaml.Node `yaml:"network"`
	DNS        yaml.Node `yaml:"dns"`
	SSL        yaml.Node `yaml:"ssl"`
	Code       yaml.Node `yaml:"code"`
	JavaScript yaml.Node `yaml:"javascript"`
	Flow       string    `yaml:"flow"`
	Variables  yaml.Node `yaml:"variables"`
	Workflows  yaml.Node `yaml:"workflows"`
}

type nRequest struct {
	Method            string            `yaml:"method"`
	Path              stringList        `yaml:"path"`
	Raw               stringList        `yaml:"raw"`
	Headers           map[string]string `yaml:"headers"`
	Body              string            `yaml:"body"`
	MatchersCondition string            `yaml:"matchers-condition"`
	Matchers          []nMatcher        `yaml:"matchers"`
	StopAtFirstMatch  bool              `yaml:"stop-at-first-match"`
	Payloads          yaml.Node         `yaml:"payloads"`
	Attack            string            `yaml:"attack"`
	Fuzzing           yaml.Node         `yaml:"fuzzing"`
}

type nMatcher struct {
	Type      string     `yaml:"type"`
	Part      string     `yaml:"part"`
	Status    []int      `yaml:"status"`
	Words     stringList `yaml:"words"`
	Regex     stringList `yaml:"regex"`
	Size      []int      `yaml:"size"`
	Condition string     `yaml:"condition"`
	Negative  bool       `yaml:"negative"`
	DSL       stringList `yaml:"dsl"`
}

// stringList accepts a YAML scalar, a comma-separated scalar (for tags), or a list.
type stringList []string

func (s *stringList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		if strings.Contains(n.Value, ",") {
			for _, p := range strings.Split(n.Value, ",") {
				if p = strings.TrimSpace(p); p != "" {
					*s = append(*s, p)
				}
			}
			return nil
		}
		if n.Value != "" {
			*s = []string{n.Value}
		}
		return nil
	case yaml.SequenceNode:
		var a []string
		if err := n.Decode(&a); err != nil {
			return err
		}
		*s = a
		return nil
	}
	return nil
}

var reBaseTokens = regexp.MustCompile(`\{\{\s*(?:BaseURL|RootURL|Hostname|Host)\s*\}\}`)

// convert maps one template to a Signature, or returns a non-empty skip reason.
func convert(data []byte, source string, techNames map[string]string) (*templatesig.Signature, string) {
	var t nTemplate
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, "parse-error"
	}
	if t.ID == "" {
		return nil, "no-id"
	}
	if present(t.Headless) || present(t.Network) || present(t.DNS) || present(t.SSL) ||
		present(t.Code) || present(t.JavaScript) || present(t.Workflows) {
		return nil, "unsupported-protocol"
	}
	if t.Flow != "" || present(t.Variables) {
		return nil, "flow-or-variables"
	}

	reqs := t.HTTP
	if len(reqs) == 0 {
		reqs = t.Requests
	}
	if len(reqs) == 0 {
		return nil, "no-http"
	}
	if len(reqs) > 1 {
		return nil, "multi-request"
	}
	nr := reqs[0]

	if present(nr.Payloads) || nr.Attack != "" || present(nr.Fuzzing) {
		return nil, "payloads"
	}
	if len(nr.Raw) > 0 {
		return nil, "raw-request"
	}
	if len(nr.Path) == 0 {
		return nil, "no-path"
	}

	var paths []string
	for _, p := range nr.Path {
		if strings.Contains(p, "{{interactsh") {
			return nil, "interactsh"
		}
		stripped := reBaseTokens.ReplaceAllString(p, "")
		if strings.Contains(stripped, "{{") {
			return nil, "dynamic-path"
		}
		paths = append(paths, stripped)
	}

	matchers, reason := convertMatchers(nr.Matchers)
	if reason != "" {
		return nil, reason
	}
	if len(matchers) == 0 {
		return nil, "no-matchers"
	}

	sig := &templatesig.Signature{
		ID:           t.ID,
		NucleiID:     t.ID,
		Name:         orDefault(t.Info.Name, t.ID),
		Severity:     strings.ToLower(t.Info.Severity),
		Description:  t.Info.Description,
		Remediation:  t.Info.Remediation,
		Reference:    t.Info.Reference,
		Tags:         t.Info.Tags,
		Source:       source,
		RequiresTech: techFromTags(t.Info.Tags, techNames),
		Requests: []templatesig.Request{{
			Method:            orDefault(strings.ToUpper(nr.Method), "GET"),
			Paths:             paths,
			Headers:           nr.Headers,
			Body:              nr.Body,
			Matchers:          matchers,
			MatchersCondition: nr.MatchersCondition,
			StopAtFirstMatch:  nr.StopAtFirstMatch,
		}},
	}
	return sig, ""
}

// convertMatchers maps nuclei matchers to the supported subset, rejecting the
// whole template on any unsupported matcher type.
func convertMatchers(in []nMatcher) ([]templatesig.Matcher, string) {
	out := make([]templatesig.Matcher, 0, len(in))
	for _, m := range in {
		switch m.Type {
		case "status":
			out = append(out, templatesig.Matcher{Type: "status", Status: m.Status, Negative: m.Negative})
		case "size":
			out = append(out, templatesig.Matcher{Type: "size", Sizes: m.Size, Negative: m.Negative})
		case "word":
			// The runtime substitutes the URL tokens nuclei expands in words; any
			// other {{...}} expression (payload refs, dsl helpers) it cannot, so a
			// word carrying one is not faithfully evaluable — drop the template.
			for _, w := range m.Words {
				if hasUnknownTemplateToken(w) {
					return nil, "matcher-template-var"
				}
			}
			out = append(out, templatesig.Matcher{
				Type: "word", Part: m.Part, Words: m.Words,
				Condition: m.Condition, Negative: m.Negative,
			})
		case "regex":
			// Regexes are precompiled before a target (and thus BaseURL) is known,
			// so a regex carrying any template token cannot be substituted; drop it.
			for _, expr := range m.Regex {
				if strings.Contains(expr, "{{") {
					return nil, "regex-template-var"
				}
				if _, err := regexp.Compile(expr); err != nil {
					return nil, "regex-re2"
				}
			}
			out = append(out, templatesig.Matcher{
				Type: "regex", Part: m.Part, Regexes: m.Regex,
				Condition: m.Condition, Negative: m.Negative,
			})
		case "dsl":
			return nil, "dsl"
		default:
			return nil, "matcher:" + m.Type
		}
	}
	return out, ""
}

// techFromTags maps a template's tags to canonical technology names present in the
// Wappalyzer database. A tag with no match contributes nothing, so a template that
// names no known technology stays tech-agnostic (runs everywhere).
func techFromTags(tags []string, techNames map[string]string) []templatesig.TechReq {
	var out []templatesig.TechReq
	seen := map[string]bool{}
	for _, tag := range tags {
		if canon, ok := techNames[strings.ToLower(strings.TrimSpace(tag))]; ok && !seen[canon] {
			seen[canon] = true
			out = append(out, templatesig.TechReq{Name: canon})
		}
	}
	return out
}

var templateTokenRe = regexp.MustCompile(`\{\{([^}]*)\}\}`)

// knownMatcherTokens are the URL tokens the runtime substitutes in word matchers.
var knownMatcherTokens = map[string]bool{
	"BaseURL": true, "RootURL": true, "Hostname": true, "Host": true,
}

// hasUnknownTemplateToken reports whether s carries a {{...}} the runtime cannot
// substitute in a matcher word.
func hasUnknownTemplateToken(s string) bool {
	for _, m := range templateTokenRe.FindAllStringSubmatch(s, -1) {
		if !knownMatcherTokens[strings.TrimSpace(m[1])] {
			return true
		}
	}
	return false
}

func present(n yaml.Node) bool { return !n.IsZero() }
func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

func printCensus(census map[string]int, outPath string) {
	keys := make([]string, 0, len(census))
	for k := range census {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return census[keys[i]] > census[keys[j]] })
	fmt.Printf("nucleigen: wrote %s\n", outPath)
	for _, k := range keys {
		fmt.Printf("  %-26s %d\n", k, census[k])
	}
}
