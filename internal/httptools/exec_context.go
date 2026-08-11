package httptools

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// maxJars bounds how many principals hold a live cookie jar at once. Well above
// any realistic token count; a backstop, not a workflow limit.
const maxJars = 32

// Contexts holds one cookie jar per automation principal, so a multi-request
// authenticated flow does not require the agent to copy cookies by hand — which it
// cannot do at all without credential visibility.
//
// Jars are in-memory only and are dropped on restart, on token rotation or
// deletion, and on a project switch.
type Contexts struct {
	mu   sync.Mutex
	jars map[string]*jarEntry
}

type jarEntry struct {
	jar  *cookiejar.Jar
	used time.Time
	// hosts records the origins this jar has seen, because cookiejar has no
	// enumeration API: listing or clearing requires a URL to ask about.
	hosts map[string]struct{}
}

func NewContexts() *Contexts {
	return &Contexts{jars: map[string]*jarEntry{}}
}

// ContextCookie is one entry in a jar, as reported by context.get.
type ContextCookie struct {
	Host  string
	Name  string
	Value string
}

func (c *Contexts) entry(tokenID string, create bool) *jarEntry {
	if c == nil || tokenID == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.jars[tokenID]; ok {
		e.used = time.Now()
		return e
	}
	if !create {
		return nil
	}
	if len(c.jars) >= maxJars {
		c.evictOldestLocked()
	}
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil
	}
	e := &jarEntry{jar: jar, used: time.Now(), hosts: map[string]struct{}{}}
	c.jars[tokenID] = e
	return e
}

func (c *Contexts) evictOldestLocked() {
	var oldestID string
	var oldest time.Time
	for id, e := range c.jars {
		if oldestID == "" || e.used.Before(oldest) {
			oldestID, oldest = id, e.used
		}
	}
	delete(c.jars, oldestID)
}

// Capture records Set-Cookie headers from a response.
func (c *Contexts) Capture(tokenID string, u *url.URL, respRaw []byte) {
	if u == nil || len(respRaw) == 0 {
		return
	}
	e := c.entry(tokenID, true)
	if e == nil {
		return
	}
	hdr, _, _ := splitRaw(respRaw)
	_, h := parseHeaderBlock(hdr)
	resp := http.Response{Header: h}
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return
	}
	c.mu.Lock()
	e.hosts[u.Host] = struct{}{}
	c.mu.Unlock()
	e.jar.SetCookies(u, cookies)
}

// Apply merges jar cookies into a raw request and reports the names it supplied.
//
// It never overrides: a cookie the request already carries wins, and if the caller
// edited the Cookie header at all the jar stays out entirely. Re-adding a session
// cookie to a request an agent deliberately stripped would manufacture a false
// negative, which is the worst outcome in an authorization test.
func (c *Contexts) Apply(tokenID string, u *url.URL, raw []byte, editedCookies bool) ([]byte, []string) {
	if u == nil || editedCookies || len(raw) == 0 {
		return raw, nil
	}
	e := c.entry(tokenID, false)
	if e == nil {
		return raw, nil
	}
	jarCookies := e.jar.Cookies(u)
	if len(jarCookies) == 0 {
		return raw, nil
	}

	present := map[string]bool{}
	hdrRaw, _, _ := splitRaw(raw)
	for _, line := range splitHeaderLines(hdrRaw) {
		if !strings.EqualFold(headerNameOf(line), "cookie") {
			continue
		}
		for _, pair := range strings.Split(headerValueOf(line), ";") {
			if n, _, ok := strings.Cut(strings.TrimSpace(pair), "="); ok {
				present[strings.TrimSpace(n)] = true
			}
		}
	}

	var add []string
	var names []string
	for _, ck := range jarCookies {
		if present[ck.Name] {
			continue
		}
		add = append(add, ck.Name+"="+ck.Value)
		names = append(names, ck.Name)
	}
	if len(add) == 0 {
		return raw, nil
	}

	joined := strings.Join(add, "; ")
	out, err := ApplyEdits(raw, []Edit{{Op: "addHeader", Name: "Cookie", Value: joined}})
	if err != nil {
		return raw, nil
	}
	return out, names
}

// List returns the jar's contents. Values are included only when the caller is
// permitted to see them.
func (c *Contexts) List(tokenID string, withValues bool) []ContextCookie {
	e := c.entry(tokenID, false)
	if e == nil {
		return nil
	}
	c.mu.Lock()
	hosts := make([]string, 0, len(e.hosts))
	for h := range e.hosts {
		hosts = append(hosts, h)
	}
	c.mu.Unlock()
	sort.Strings(hosts)

	var out []ContextCookie
	for _, h := range hosts {
		for _, ck := range e.jar.Cookies(&url.URL{Scheme: "https", Host: h, Path: "/"}) {
			entry := ContextCookie{Host: h, Name: ck.Name}
			if withValues {
				entry.Value = ck.Value
			}
			out = append(out, entry)
		}
	}
	return out
}

// Clear drops the whole jar, or expires every cookie for one host. It reports how
// many cookies it removed.
func (c *Contexts) Clear(tokenID, host string) int {
	if c == nil || tokenID == "" {
		return 0
	}
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		n := len(c.List(tokenID, false))
		c.mu.Lock()
		delete(c.jars, tokenID)
		c.mu.Unlock()
		return n
	}

	e := c.entry(tokenID, false)
	if e == nil {
		return 0
	}
	u := &url.URL{Scheme: "https", Host: host, Path: "/"}
	existing := e.jar.Cookies(u)
	if len(existing) == 0 {
		return 0
	}
	expired := make([]*http.Cookie, 0, len(existing))
	for _, ck := range existing {
		expired = append(expired, &http.Cookie{Name: ck.Name, Value: "", MaxAge: -1, Path: "/"})
	}
	e.jar.SetCookies(u, expired)
	c.mu.Lock()
	delete(e.hosts, host)
	c.mu.Unlock()
	return len(existing)
}

// Reset drops one principal's jar. ResetAll drops every jar, which is what a
// project switch does: a session from a previous engagement must not be replayed
// into a new one.
func (c *Contexts) Reset(tokenID string) { c.Clear(tokenID, "") }

func (c *Contexts) ResetAll() {
	if c == nil {
		return
	}
	c.mu.Lock()
	clear(c.jars)
	c.mu.Unlock()
}

// requestURL builds the URL a send will dial, for jar matching. The path matters:
// cookies are path-scoped.
func requestURL(scheme, host string, raw []byte) *url.URL {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme != "http" && scheme != "https" {
		scheme = "https"
	}
	if strings.TrimSpace(host) == "" {
		return nil
	}
	path := "/"
	if _, target, _, ok := requestLine(firstLine(raw)); ok {
		if p, _ := splitTarget(target); strings.HasPrefix(p, "/") {
			path = p
		}
	}
	return &url.URL{Scheme: scheme, Host: host, Path: path}
}

// editsTouchCookies reports whether the caller controlled the Cookie header
// itself, in which case the jar must not second-guess it.
func editsTouchCookies(edits []Edit) bool {
	return slices.ContainsFunc(edits, func(e Edit) bool {
		switch e.Op {
		case "setHeader", "addHeader", "removeHeader":
			return strings.EqualFold(strings.TrimSpace(e.Name), "cookie")
		}
		return false
	})
}

func headerValueOf(line string) string {
	_, v, _ := strings.Cut(line, ":")
	return strings.TrimSpace(v)
}

// contextNote renders the "the jar supplied these" line appended to a send result.
func contextNote(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return fmt.Sprintf("context: supplied cookie %s (not in your request; use useContext=false to send without)",
		strings.Join(names, ", "))
}
