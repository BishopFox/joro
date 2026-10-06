// DOM XSS sink monitor, injected by internal/activescan/domxss via CDP's
// Page.addScriptToEvaluateOnNewDocument, so it runs before any page script and is
// not subject to the page's CSP.
//
// It wraps the dangerous DOM sinks and, whenever one receives a value containing
// a Joro canary token, reports the sink, the source channel the canary came from
// (hash / query / window.name) and a stack trace back to Go through the
// __joroDomXss binding. It never throws into the page.
(function () {
  try {
    var MARK = "__joroDX_";
    var reported = {};

    function channelSource(ch) {
      if (ch === "h") return "location.hash";
      if (ch === "q") return "location.search";
      if (ch === "n") return "window.name";
      return "unknown";
    }

    function scan(val, sink) {
      if (val == null) return;
      var s;
      try { s = String(val); } catch (e) { return; }
      if (s.indexOf(MARK) < 0) return;
      var m = s.match(/__joroDX_([hqn])_([0-9a-f]+)/);
      if (!m) return;
      var channel = m[1];
      var token = m[0];
      var key = sink + "|" + channel + "|" + token;
      if (reported[key]) return;
      reported[key] = true;

      var payload = {
        sink: sink,
        source: channelSource(channel),
        channel: channel,
        token: token,
        value: s.length > 2000 ? s.slice(0, 2000) : s,
        url: "",
        stack: ""
      };
      try { payload.url = location.href; } catch (e) {}
      try { payload.stack = (new Error()).stack || ""; } catch (e) {}
      try { window.__joroDomXss(JSON.stringify(payload)); } catch (e) {}
    }

    function hookProp(proto, prop, sink) {
      try {
        var d = Object.getOwnPropertyDescriptor(proto, prop);
        if (!d || !d.set) return;
        var origSet = d.set;
        Object.defineProperty(proto, prop, {
          configurable: true,
          enumerable: d.enumerable,
          get: d.get,
          set: function (v) { scan(v, sink); return origSet.call(this, v); }
        });
      } catch (e) {}
    }
    hookProp(Element.prototype, "innerHTML", "Element.innerHTML");
    hookProp(Element.prototype, "outerHTML", "Element.outerHTML");

    try {
      var iah = Element.prototype.insertAdjacentHTML;
      Element.prototype.insertAdjacentHTML = function (pos, html) {
        scan(html, "insertAdjacentHTML");
        return iah.apply(this, arguments);
      };
    } catch (e) {}

    function hookDocWrite(name) {
      try {
        var orig = document[name];
        document[name] = function () {
          for (var i = 0; i < arguments.length; i++) scan(arguments[i], "document." + name);
          return orig.apply(this, arguments);
        };
      } catch (e) {}
    }
    hookDocWrite("write");
    hookDocWrite("writeln");

    try {
      var _eval = window.eval;
      window.eval = function (code) { scan(code, "eval"); return _eval(code); };
    } catch (e) {}
    try {
      var _Func = window.Function;
      window.Function = function () {
        for (var i = 0; i < arguments.length; i++) scan(arguments[i], "Function");
        return _Func.apply(this, arguments);
      };
    } catch (e) {}

    function hookTimer(name) {
      try {
        var orig = window[name];
        window[name] = function (fn) {
          if (typeof fn === "string") scan(fn, name + "(string)");
          return orig.apply(this, arguments);
        };
      } catch (e) {}
    }
    hookTimer("setTimeout");
    hookTimer("setInterval");

    try {
      var _setAttr = Element.prototype.setAttribute;
      Element.prototype.setAttribute = function (name, value) {
        try {
          var n = ("" + name).toLowerCase();
          if (n === "src" || n === "href" || n === "data" || n === "action" ||
              n === "formaction" || n.indexOf("on") === 0) {
            scan(value, "setAttribute(" + n + ")");
          }
        } catch (e) {}
        return _setAttr.apply(this, arguments);
      };
    } catch (e) {}

    function hookJQuery() {
      try {
        var jq = window.jQuery;
        if (!jq || !jq.fn) return;
        ["html", "append", "prepend", "after", "before", "replaceWith"].forEach(function (mth) {
          var orig = jq.fn[mth];
          if (typeof orig !== "function") return;
          jq.fn[mth] = function () {
            for (var i = 0; i < arguments.length; i++) {
              if (typeof arguments[i] === "string") scan(arguments[i], "jQuery." + mth);
            }
            return orig.apply(this, arguments);
          };
        });
      } catch (e) {}
    }
    hookJQuery();
    try { document.addEventListener("DOMContentLoaded", hookJQuery); } catch (e) {}
  } catch (e) {}
})();
