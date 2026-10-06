// Package domxss is the first internal/activescan rule: it confirms DOM-based XSS
// by driving a headless browser over CDP.
//
// For each target URL it plants a distinct canary token in each controllable DOM
// source — the URL fragment, a query value and window.name — then navigates to
// the URL. A monitor shim (monitor.js), injected before any page script runs and
// so unaffected by the page's CSP, wraps the dangerous sinks (innerHTML, eval,
// document.write, setAttribute, jQuery.html, …). When a canary reaches a sink the
// shim reports which one and from which source over a CDP binding, and that
// becomes a high-confidence detect.Finding.
//
// Per-source canaries make attribution exact: because the hash, query and name
// tokens differ, a sink hit names the precise source that reached it rather than
// guessing from whichever source happened to hold the payload.
package domxss

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/activescan"
	"github.com/BishopFox/joro/internal/browser"
	"github.com/BishopFox/joro/internal/cdp"
	"github.com/BishopFox/joro/internal/detect"
)

//go:embed monitor.js
var monitorJS string

const (
	ruleID      = "domxss"
	bindingName = "__joroDomXss"
	findingRule = "activescan.domxss"

	connectTimeout = 20 * time.Second
	perURLTimeout  = 15 * time.Second
	settleDelay    = 1200 * time.Millisecond
)

// Rule implements activescan.Rule.
type Rule struct{}

// New returns the DOM XSS rule.
func New() *Rule { return &Rule{} }

func (*Rule) ID() string                { return ruleID }
func (*Rule) Name() string              { return "DOM-based XSS" }
func (*Rule) Category() detect.Category { return detect.CategoryDOMXSS }

// hit is one sink report from the injected monitor.
type hit struct {
	Sink    string `json:"sink"`
	Source  string `json:"source"`
	Channel string `json:"channel"`
	Token   string `json:"token"`
	Value   string `json:"value"`
	URL     string `json:"url"`
	Stack   string `json:"stack"`
}

// collector gathers monitor reports as they arrive on the CDP read loop.
type collector struct {
	mu   sync.Mutex
	hits []hit
}

func (c *collector) add(h hit) {
	c.mu.Lock()
	c.hits = append(c.hits, h)
	c.mu.Unlock()
}

// drain returns every hit received since it was last called.
func (c *collector) drain() []hit {
	c.mu.Lock()
	out := c.hits
	c.hits = nil
	c.mu.Unlock()
	return out
}

// Run launches a dedicated headless browser, injects the monitor, and navigates
// each target URL with canaries, reporting confirmed flows.
func (r *Rule) Run(ctx context.Context, t activescan.Target, deps activescan.RuleDeps, rep activescan.Reporter) error {
	if deps.CA == nil {
		return fmt.Errorf("no CA available for the scan browser")
	}
	path, _, ok := browser.Find()
	if !ok {
		return fmt.Errorf("no Chromium-family browser found to drive the scan")
	}

	profileDir := filepath.Join(deps.DataDir, "browser-profiles", "__scan")
	sess, err := browser.LaunchControlled(browser.LaunchOptions{
		BrowserPath:     path,
		ProxyAddr:       deps.ProxyAddr,
		SPKIFingerprint: browser.SPKIFingerprint(deps.CA.Cert),
		ProfileDir:      profileDir,
		Headless:        true,
	})
	if err != nil {
		return fmt.Errorf("launch scan browser: %w", err)
	}
	defer sess.Kill(true)

	client, err := cdp.Connect(ctx, sess.DebugPort, connectTimeout)
	if err != nil {
		return err
	}
	defer client.Close()

	col := &collector{}
	loadCh := make(chan struct{}, 1)
	client.On("Page.loadEventFired", func(json.RawMessage) {
		select {
		case loadCh <- struct{}{}:
		default:
		}
	})
	client.On("Runtime.bindingCalled", func(params json.RawMessage) {
		var p struct {
			Name    string `json:"name"`
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(params, &p); err != nil || p.Name != bindingName {
			return
		}
		var h hit
		if err := json.Unmarshal([]byte(p.Payload), &h); err == nil {
			col.add(h)
		}
	})

	if _, err := client.Send(ctx, "Page.enable", nil); err != nil {
		return err
	}
	if _, err := client.Send(ctx, "Runtime.enable", nil); err != nil {
		return err
	}
	if _, err := client.Send(ctx, "Runtime.addBinding", map[string]any{"name": bindingName}); err != nil {
		return err
	}
	if _, err := client.Send(ctx, "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": monitorJS}); err != nil {
		return err
	}

	for _, tu := range t.URLs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		scanURL(ctx, client, col, loadCh, t.Host, tu.URL, rep)
		rep.Progress(1)
	}
	return nil
}

// scanURL plants canaries, navigates, waits for load plus a settle delay, and
// files any confirmed hits.
func scanURL(ctx context.Context, client *cdp.Client, col *collector, loadCh chan struct{}, host, rawURL string, rep activescan.Reporter) {
	navURL, nameCanary := buildCanaryURL(rawURL)
	if navURL == "" {
		return
	}

	// window.name persists across the navigation, so set it first.
	_, _ = client.Send(ctx, "Runtime.evaluate", map[string]any{
		"expression":    "window.name=" + jsString(nameCanary),
		"returnByValue": true,
	})

	// Drop any stale load signal from a previous navigation.
	select {
	case <-loadCh:
	default:
	}

	urlCtx, cancel := context.WithTimeout(ctx, perURLTimeout)
	defer cancel()
	if _, err := client.Send(urlCtx, "Page.navigate", map[string]any{"url": navURL}); err != nil {
		return
	}
	// Wait for the load event (or the per-URL timeout), then give async sinks a
	// moment after load to fire.
	select {
	case <-urlCtx.Done():
		return
	case <-loadCh:
	}
	select {
	case <-urlCtx.Done():
	case <-time.After(settleDelay):
	}

	seen := map[string]bool{}
	for _, h := range col.drain() {
		key := h.Source + "|" + h.Sink
		if seen[key] {
			continue
		}
		seen[key] = true
		rep.Finding(finding(host, navURL, h))
	}
}

// buildCanaryURL returns the URL to navigate, carrying a hash and query canary,
// plus the distinct window.name canary to set beforehand. It returns "" if the
// URL cannot be parsed.
func buildCanaryURL(rawURL string) (navURL, nameCanary string) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", ""
	}
	q := u.Query()
	q.Set("joroqp", canary("q"))
	u.RawQuery = q.Encode()
	u.Fragment = canary("h")
	return u.String(), canary("n")
}

// canary mints a per-source token the monitor recognizes: __joroDX_<channel>_<hex>.
func canary(channel string) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "__joroDX_" + channel + "_" + hex.EncodeToString(b[:])
}

// finding builds the detect.Finding for a confirmed sink hit.
func finding(host, navURL string, h hit) detect.Finding {
	now := time.Now()
	path := navURL
	if u, err := url.Parse(navURL); err == nil {
		path = u.Path
	}
	evidence := fmt.Sprintf("%s reached %s (via %s)", h.Source, h.Sink, h.Channel)
	if h.Stack != "" {
		evidence += "\n" + firstLines(h.Stack, 6)
	}
	return detect.Finding{
		ID:             detect.FindingID(findingRule, host, h.Source+"|"+h.Sink+"|"+path),
		RuleID:         findingRule,
		RuleName:       "DOM-based XSS",
		Category:       detect.CategoryDOMXSS,
		Severity:       detect.SeverityHigh,
		Confidence:     detect.ConfidenceHigh,
		Target:         detect.TargetMessage,
		Host:           host,
		Method:         "GET",
		URL:            navURL,
		Detail:         h.Source + " reaches " + h.Sink,
		Evidence:       evidence,
		FirstSeen:      now,
		LastSeen:       now,
		EvidenceOffset: -1,
	}
}

// jsString encodes s as a JavaScript string literal for Runtime.evaluate.
func jsString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// firstLines returns at most n lines of s.
func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
