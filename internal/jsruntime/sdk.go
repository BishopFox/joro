package jsruntime

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Binding maps one name in the JavaScript SDK to one capability ID.
//
// This table is the contract, in both directions. The shim injected into the VM is
// generated from it, and the grant bundle the host authorizes a run with is generated
// from it too — so it is impossible to expose a JavaScript method that is not granted,
// or to grant a capability with no way to call it. Adding a method to the SDK and
// widening the bundle are the same edit, which is the property worth having.
//
// JS is a two-segment path: joro.<namespace>.<method>. It is allowed to differ from
// Cap, and does where the capability ID carries a grouping the script has no reason
// to repeat — config.intercept.get reads better as joro.intercept.get, and a script
// asking for detect rules wants joro.detect.rules, not joro.detect.rules.list.
//
// Keeping the generic bridge private, rather than exposing invoke(id, args) to script
// authors, is what leaves room to rename a capability, validate an argument, or
// deprecate a method without every raw capability ID becoming public API forever.
type Binding struct {
	JS  string
	Cap string
}

// Bindings is the Automation SDK v1 surface: the reads and writes ordinary web
// security automation needs, and nothing administrative.
//
// Excluded on purpose, and each for its own reason:
//
//   - config.*.edit — a script adding a Match & Replace rule silently rewrites the
//     operator's own traffic. Engagement setup is a different job with its own token
//     profile.
//   - detect.* writes, including rescan — same argument: they change what the
//     operator sees rather than what the script learns.
//   - scope.addrule / scope.enable — these are UnrestrictedOnly, and a run pins
//     RequireScope, so including one would fail the profile validation at startup.
//     That is the intended outcome: scope is the control that bounds the run.
//   - exec.* and c2.* — command execution and an operator's C2 are granted one at a
//     time by hand, never bundled.
//   - script.* — a script that can start scripts launders its own budget.
var Bindings = []Binding{
	{JS: "instance.get", Cap: "instance.get"},

	{JS: "history.list", Cap: "history.list"},
	{JS: "history.stats", Cap: "history.stats"},

	{JS: "sitemap.get", Cap: "sitemap.get"},
	{JS: "scope.get", Cap: "scope.get"},

	{JS: "http.fingerprint", Cap: "http.fingerprint"},
	{JS: "http.read", Cap: "http.read"},
	{JS: "http.search", Cap: "http.search"},
	{JS: "http.diff", Cap: "http.diff"},
	{JS: "http.resend", Cap: "http.resend"},
	{JS: "http.batch", Cap: "http.batch"},

	{JS: "websocket.list", Cap: "websocket.list"},

	{JS: "fuzzer.start", Cap: "fuzzer.start"},
	{JS: "fuzzer.status", Cap: "fuzzer.status"},
	{JS: "fuzzer.results", Cap: "fuzzer.results"},
	{JS: "fuzzer.stop", Cap: "fuzzer.stop"},

	{JS: "findings.list", Cap: "findings.list"},
	{JS: "findings.get", Cap: "findings.get"},
	{JS: "findings.create", Cap: "findings.create"},
	{JS: "findings.update", Cap: "findings.update"},

	{JS: "notes.list", Cap: "notes.list"},
	{JS: "notes.hosts", Cap: "notes.hosts"},
	{JS: "notes.create", Cap: "notes.create"},

	{JS: "context.get", Cap: "context.get"},
	{JS: "context.clear", Cap: "context.clear"},

	{JS: "intercept.get", Cap: "config.intercept.get"},
	{JS: "intercept.list", Cap: "config.intercept.list"},

	{JS: "detect.rules", Cap: "detect.rules.list"},
	{JS: "detect.config", Cap: "detect.config.get"},
}

// CapabilityIDs returns the capability IDs the SDK can reach, sorted and deduplicated.
// This is the grant list a run is authorized with.
func CapabilityIDs() []string {
	seen := make(map[string]struct{}, len(Bindings))
	out := make([]string, 0, len(Bindings))
	for _, b := range Bindings {
		if _, dup := seen[b.Cap]; dup {
			continue
		}
		seen[b.Cap] = struct{}{}
		out = append(out, b.Cap)
	}
	sort.Strings(out)
	return out
}

// shimSource generates the JavaScript that builds the frozen joro global.
//
// The shim runs before user code and takes the raw bridge function off the global
// object, closes over it, and deletes it. After that the only way to reach the host is
// through a frozen namespace, so a script cannot rebind joro.http.resend to something
// that logs its arguments and forwards, and cannot call a capability the table does
// not name.
func shimSource() string {
	var b strings.Builder
	b.WriteString(`(function () {
	"use strict";
	var invoke = globalThis.__joro_invoke;
	var log = globalThis.__joro_log;
	delete globalThis.__joro_invoke;
	delete globalThis.__joro_log;

	// GoError is goja's own constructor for errors carrying a Go value. Nothing here
	// ever puts a Go error into the VM — failures arrive as JSON and are thrown as
	// ordinary Errors — so it can only ever be a confusing thing for a script to
	// find. Removed so the global object holds no host-flavored type at all.
	delete globalThis.GoError;

	// console is built here rather than in Go so that formatting happens in
	// JavaScript and only a finished string crosses the bridge. Exporting a goja
	// value to Go to inspect it would put the host in the business of reflecting
	// over script data, which is the one thing this boundary exists to avoid.
	function fmt(v) {
		if (typeof v === "string") { return v; }
		if (v === undefined) { return "undefined"; }
		if (typeof v === "bigint") { return v.toString() + "n"; }
		if (v instanceof Error) {
			return (v.name || "Error") + ": " + (v.message || "") + (v.code ? " [" + v.code + "]" : "");
		}
		try {
			var s = JSON.stringify(v);
			return s === undefined ? String(v) : s;
		} catch (e) {
			return String(v);
		}
	}
	function mk(level) {
		return function () {
			var parts = [];
			for (var i = 0; i < arguments.length; i++) { parts.push(fmt(arguments[i])); }
			log(level, parts.join(" "));
		};
	}
	var con = {
		log: mk("info"), info: mk("info"), warn: mk("warn"),
		error: mk("error"), debug: mk("debug"), trace: mk("debug")
	};
	Object.freeze(con);
	Object.defineProperty(globalThis, "console", {
		value: con, writable: false, enumerable: false, configurable: false
	});

	function call(id) {
		return function (args) {
			var res = JSON.parse(invoke(id, JSON.stringify(args === undefined ? {} : args)));
			if (res.ok) { return res.data; }
			var e = new Error(res.message || res.code || "capability call failed");
			e.name = "JoroCapabilityError";
			e.code = res.code || "";
			e.capability = id;
			throw e;
		};
	}

	var joro = {};
	function ns(name) {
		if (!Object.prototype.hasOwnProperty.call(joro, name)) { joro[name] = {}; }
		return joro[name];
	}
`)

	// Emit in table order so the generated source is stable and reviewable.
	for _, bind := range Bindings {
		nsName, method, ok := splitJSPath(bind.JS)
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "\tns(%q)[%q] = call(%q);\n", nsName, method, bind.Cap)
	}

	b.WriteString(`
	Object.keys(joro).forEach(function (k) { Object.freeze(joro[k]); });
	Object.freeze(joro);
	Object.defineProperty(globalThis, "joro", {
		value: joro, writable: false, enumerable: true, configurable: false
	});
})();
`)
	return b.String()
}

func splitJSPath(p string) (ns, method string, ok bool) {
	i := strings.IndexByte(p, '.')
	if i <= 0 || i == len(p)-1 {
		return "", "", false
	}
	return p[:i], p[i+1:], true
}

// The module specifier the SDK is published under. The runtime has no module system —
// joro is a global — but generated code idiomatically writes the import, and a
// TypeScript author needs a name to import types from, so a preamble naming exactly
// this specifier is accepted and erased.
const SDKModule = "@joro/sdk"

var (
	// import <clause> from "<spec>"
	reImportFrom = regexp.MustCompile(`(?m)^[ \t]*import\b[^;\n]*?from[ \t]*['"]([^'"\n]*)['"][ \t]*;?`)
	// import "<spec>"
	reImportBare = regexp.MustCompile(`(?m)^[ \t]*import[ \t]+['"]([^'"\n]*)['"][ \t]*;?`)
	// export [default] <decl>
	reExportDecl = regexp.MustCompile(`(?m)^([ \t]*)export[ \t]+(default[ \t]+)?((?:async[ \t]+)?(?:function|const|let|var|class)\b)`)
	// export { ... }
	reExportList = regexp.MustCompile(`(?m)^[ \t]*export[ \t]*\{[^}\n]*\}[ \t]*;?`)
)

// Prepare validates a program and erases the module preamble the runtime does not
// implement.
//
// Every erasure is replaced with spaces of equal length rather than deleted, so byte
// offsets, line numbers and columns are untouched and a stack trace still points at
// the line the author wrote.
//
// An import of anything other than the SDK is an error, never a silent rewrite. The
// alternative — dropping it and letting the script fail later on an undefined symbol —
// would report a missing variable when the real problem is that host module resolution
// does not exist and third-party code has to be bundled before it gets here.
func Prepare(source string) (string, error) {
	if strings.TrimSpace(source) == "" {
		return "", fmt.Errorf("script is empty: define an entry point, for example `async function run(ctx) { ... }`")
	}
	if len(source) > MaxSourceBytes {
		return "", fmt.Errorf("script is %d bytes, over the %d byte limit", len(source), MaxSourceBytes)
	}

	out := source
	for _, re := range []*regexp.Regexp{reImportFrom, reImportBare} {
		var bad string
		out = replaceIndexed(out, re, func(groups []string) bool {
			if groups[1] != SDKModule {
				if bad == "" {
					bad = groups[1]
				}
				return false
			}
			return true
		})
		if bad != "" {
			return "", fmt.Errorf(
				"cannot import %q: the only importable module is %q, and it does not need importing — "+
					"joro is already a global. Bundle third-party code into the script before running it",
				bad, SDKModule)
		}
	}

	// `export` is meaningless without a module system, but generated code writes it,
	// and erasing the keyword leaves a declaration that behaves identically.
	out = replaceIndexed(out, reExportList, func([]string) bool { return true })
	out = reExportDecl.ReplaceAllStringFunc(out, func(m string) string {
		g := reExportDecl.FindStringSubmatch(m)
		// Keep the indentation and the declaration keyword; blank the rest so the
		// length is preserved.
		keep := g[1] + g[3]
		return keep + strings.Repeat(" ", len(m)-len(keep))
	})

	return out, nil
}

// replaceIndexed blanks every match for which keep reports true, preserving length.
// A match the callback rejects is left in place, which lets the caller report it.
func replaceIndexed(s string, re *regexp.Regexp, keep func(groups []string) bool) string {
	matches := re.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return s
	}
	b := []byte(s)
	for _, m := range matches {
		groups := make([]string, len(m)/2)
		for i := range groups {
			if m[2*i] >= 0 {
				groups[i] = s[m[2*i]:m[2*i+1]]
			}
		}
		if !keep(groups) {
			continue
		}
		for i := m[0]; i < m[1]; i++ {
			if b[i] != '\n' && b[i] != '\r' {
				b[i] = ' '
			}
		}
	}
	return string(b)
}
