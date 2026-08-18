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
	{JS: "history.highlight", Cap: "history.highlight"},

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
	var storage = globalThis.__joro_storage;
	delete globalThis.__joro_invoke;
	delete globalThis.__joro_log;
	delete globalThis.__joro_storage;

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

	// atob and btoa, in JavaScript, because goja ships neither and a lens is handed its
	// bytes as base64. Strings only, so nothing here reaches the host.
	var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	function btoaImpl(input) {
		var s = String(input), out = "", i = 0;
		while (i < s.length) {
			var c1 = s.charCodeAt(i++);
			var c2 = i < s.length ? s.charCodeAt(i++) : NaN;
			var c3 = i < s.length ? s.charCodeAt(i++) : NaN;
			if (c1 > 255 || c2 > 255 || c3 > 255) {
				throw new Error("btoa: string holds a character outside the Latin-1 range");
			}
			var e2 = ((c1 & 3) << 4) | (c2 !== c2 ? 0 : c2 >> 4);
			var e3 = c2 !== c2 ? 64 : (((c2 & 15) << 2) | (c3 !== c3 ? 0 : c3 >> 6));
			var e4 = c3 !== c3 ? 64 : (c3 & 63);
			out += B64.charAt(c1 >> 2) + B64.charAt(e2) +
				(e3 === 64 ? "=" : B64.charAt(e3)) +
				(e4 === 64 ? "=" : B64.charAt(e4));
		}
		return out;
	}
	function atobImpl(input) {
		var s = String(input).replace(/[ \t\n\f\r]/g, "").replace(/=+$/, "");
		if (s.length % 4 === 1) { throw new Error("atob: not a valid base64 string"); }
		var out = "", buf = 0, bits = 0;
		for (var i = 0; i < s.length; i++) {
			var v = B64.indexOf(s.charAt(i));
			if (v < 0) { throw new Error("atob: not a valid base64 string"); }
			buf = (buf << 6) | v;
			bits += 6;
			if (bits >= 8) { bits -= 8; out += String.fromCharCode((buf >> bits) & 255); }
		}
		return out;
	}
	Object.defineProperty(globalThis, "atob", {
		value: atobImpl, writable: false, enumerable: false, configurable: false
	});
	Object.defineProperty(globalThis, "btoa", {
		value: btoaImpl, writable: false, enumerable: false, configurable: false
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

	// storage is emitted unconditionally, and whether this run actually has a namespace
	// is the host's answer at call time. That keeps the shim a single compiled program
	// shared by every run rather than one generated per run.
	b.WriteString(`
	function storageOp(op) {
		return function (key, value) {
			var res = JSON.parse(storage(
				op,
				key === undefined || key === null ? "" : String(key),
				JSON.stringify(value === undefined ? null : value)
			));
			if (res.ok) { return res.data; }
			var e = new Error(res.message || res.code || "storage call failed");
			e.name = "JoroStorageError";
			e.code = res.code || "";
			throw e;
		};
	}
	var st = ns("storage");
	st.get = storageOp("get");
	st.set = storageOp("set");
	st["delete"] = storageOp("delete");
	st.keys = storageOp("keys");
`)

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

// Prepare validates a program and erases the module syntax the runtime does not implement.
//
// Every erasure is replaced with spaces of equal length rather than deleted, so byte
// offsets, line numbers and columns are untouched and a stack trace still points at the
// line the author wrote.
//
// An import of anything other than the SDK is an error, never a silent rewrite. The
// alternative — dropping it and letting the script fail later on an undefined symbol —
// would report a missing variable when the real problem is that host module resolution
// does not exist and third-party code has to be bundled before it gets here.
//
// Erasure applies only to module syntax in *code* position. Without that, a template
// literal holding `export const x = 1` would be silently rewritten and a string holding
// `import y from "lodash"` would reject the whole program — either way the source an
// operator reads back would not be the source that ran, which is the one property the run
// log exists to provide.
func Prepare(source string) (string, error) {
	if strings.TrimSpace(source) == "" {
		return "", fmt.Errorf("script is empty: define an entry point, for example `async function run(ctx) { ... }`")
	}
	if len(source) > MaxSourceBytes {
		return "", fmt.Errorf("script is %d bytes, over the %d byte limit", len(source), MaxSourceBytes)
	}

	out := source
	// Computed once: blanking preserves length, so offsets stay valid across passes.
	mask := codeMask(out)

	whole := func(m []int) (int, int) { return m[0], m[1] }

	for _, re := range []*regexp.Regexp{reImportFrom, reImportBare} {
		var bad string
		out = blankMatches(out, mask, re, whole, func(groups []string) bool {
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

	// `export` is meaningless without a module system, but generated code writes it, and
	// erasing the keyword leaves a declaration that behaves identically.
	out = blankMatches(out, mask, reExportList, whole, func([]string) bool { return true })
	out = blankMatches(out, mask, reExportDecl,
		// Keep the indentation and the declaration keyword; blank only "export" and an
		// optional "default" between them.
		func(m []int) (int, int) { return m[3], m[6] },
		func([]string) bool { return true })

	return out, nil
}

// blankMatches overwrites part of each match with spaces, skipping any match that does not
// begin in code position and any the keep callback rejects. A rejected match is left in
// place so the caller can report it.
func blankMatches(
	s string, mask []bool, re *regexp.Regexp,
	span func(m []int) (from, to int), keep func(groups []string) bool,
) string {
	matches := re.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return s
	}
	b := []byte(s)
	for _, m := range matches {
		if m[0] >= len(mask) || !mask[m[0]] {
			continue
		}
		groups := make([]string, len(m)/2)
		for i := range groups {
			if m[2*i] >= 0 {
				groups[i] = s[m[2*i]:m[2*i+1]]
			}
		}
		if !keep(groups) {
			continue
		}
		from, to := span(m)
		for i := from; i < to && i < len(b); i++ {
			if b[i] != '\n' && b[i] != '\r' {
				b[i] = ' '
			}
		}
	}
	return string(b)
}

// codeMask marks the bytes of src that are program text rather than the inside of a
// string, template literal or comment.
//
// One pass, tracking the nesting that matters: line and block comments, the three quote
// forms with their escapes, and `${}` inside a template, which can hold arbitrary code
// including another template.
//
// Regex literals are deliberately not tracked — telling `/` as division from `/` as the
// start of a regex needs the parser. The consequence is bounded and in the safe direction:
// a `//` sequence inside a regex literal reads as a comment, so the rest of that line is
// marked non-code and simply escapes erasure. Less rewriting, never more.
func codeMask(src string) []bool {
	mask := make([]bool, len(src))

	// tplBraces records, for each enclosing ${} substitution, the brace depth it began at;
	// returning to that depth means the substitution closed and we are back in a template.
	var tplBraces []int
	braces, inTpl, i := 0, false, 0

	for i < len(src) {
		c := src[i]

		if inTpl {
			switch {
			case c == '\\' && i+1 < len(src):
				i += 2
			case c == '`':
				inTpl = false
				i++
			case c == '$' && i+1 < len(src) && src[i+1] == '{':
				tplBraces = append(tplBraces, braces)
				braces++
				inTpl = false
				i += 2
			default:
				i++
			}
			continue
		}

		switch c {
		case '/':
			if i+1 < len(src) && src[i+1] == '/' {
				for i < len(src) && src[i] != '\n' {
					i++
				}
				continue
			}
			if i+1 < len(src) && src[i+1] == '*' {
				i += 2
				for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
					i++
				}
				i = min(i+2, len(src))
				continue
			}
		case '\'', '"':
			q := c
			i++
			for i < len(src) {
				if src[i] == '\\' {
					i += 2
					continue
				}
				if src[i] == q || src[i] == '\n' {
					i++
					break
				}
				i++
			}
			continue
		case '`':
			inTpl = true
			i++
			continue
		case '{':
			braces++
		case '}':
			braces--
			if n := len(tplBraces); n > 0 && braces == tplBraces[n-1] {
				tplBraces = tplBraces[:n-1]
				inTpl = true
			}
		}

		mask[i] = true
		i++
	}
	return mask
}
