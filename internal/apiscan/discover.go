package apiscan

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/apispec"
	"github.com/BishopFox/joro/internal/httptools"
)

// PlanDiscovery builds the candidate list and validates the target.
func PlanDiscovery(cfg Config) ([]string, error) {
	// The same rule the render path applies. Discovery builds its probes by
	// concatenation, so without this it is the one send path with no guard on
	// where it points.
	if err := apispec.ValidateHost(cfg.Host); err != nil {
		return nil, err
	}
	scheme := strings.ToLower(cfg.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("scheme must be http or https")
	}
	paths := apispec.CandidatePaths(cfg.BasePath, cfg.CandidateSet)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no candidates to try")
	}
	return paths, nil
}

// Discover sweeps a host for API description documents.
//
// Two differences from sj's brute, both deliberate. It reports every document it
// finds rather than stopping at the first: a tab has a list, and a target
// routinely serves /v2/api-docs alongside /v3/api-docs, or a public document
// beside an internal one, and the second is often the interesting one. And a
// reference discovered in a page is followed only when it stays on the run's own
// host — sj resolves any absolute reference, which lets a page the target
// controls redirect the sweep onto a third party.
func Discover(ctx context.Context, run *Run, paths []string, d Deps, onSpec func(*apispec.Spec, []byte)) {
	cfg := run.Config

	conc := clampInt(cfg.Concurrency, DefaultDiscoveryConcurrency, 1, MaxConcurrency)
	perItem := time.Duration(clampInt(cfg.TimeoutMs, DefaultTimeoutMs, 1000, MaxTimeoutMs)) * time.Millisecond
	budget := time.Duration(clampInt(cfg.BudgetMs, DefaultBudgetMs, 1000, MaxBudgetMs)) * time.Millisecond

	runCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	run.setCancel(cancel)

	var limiter <-chan time.Time
	if cfg.RatePerSec > 0 {
		rate := min(cfg.RatePerSec, MaxRatePerSec)
		tick := time.NewTicker(time.Duration(float64(time.Second) / rate))
		defer tick.Stop()
		limiter = tick.C
	}

	sendDeps := d.Send
	sendDeps.Claims = httptools.NewClaimSet()

	origin := cfg.Scheme + "://" + cfg.Host
	start := time.Now()
	broadcast(d, "spec.run.started", map[string]any{
		"runId": run.ID, "kind": string(run.Kind), "total": run.Total, "host": cfg.Host,
	})

	// seen guards both the enumerated candidates and anything followed out of a
	// page, so a reference back to a path already tried costs nothing.
	var seenMu sync.Mutex
	seen := map[string]bool{}
	follows := 0

	claimFollow := func(u string) bool {
		seenMu.Lock()
		defer seenMu.Unlock()
		if seen[u] || follows >= MaxDiscoveryFollows {
			return false
		}
		seen[u] = true
		follows++
		return true
	}

	var stopped bool
	var stopOnce sync.Once
	halt := func(reason string) {
		stopOnce.Do(func() {
			stopped = true
			broadcast(d, "spec.run.warning", map[string]any{
				"runId": run.ID, "kind": "challenge", "detail": reason,
			})
			cancel()
		})
	}

	// Declared before assignment because it follows references by calling itself.
	var probe func(target string, depth int)
	probe = func(target string, depth int) {
		if runCtx.Err() != nil {
			return
		}
		raw := "GET " + pathOf(target) + " HTTP/1.1\r\nHost: " + cfg.Host + "\r\n" +
			"User-Agent: " + apispec.UserAgentOr(cfg.UserAgent) + "\r\n" +
			"Accept: application/json, text/yaml, text/html, */*\r\n\r\n"

		itemCtx, itemCancel := context.WithTimeout(runCtx, perItem)
		sent, err := httptools.SendViaProxy(itemCtx, []byte(raw), cfg.Scheme, cfg.Host, sendDeps)
		itemCancel()

		res := Result{URL: target, Method: "GET", Path: pathOf(target)}
		if err != nil {
			res.Error = shortErr(err)
			res.Triage = TriageWarn
			res.BodyKind = apispec.KindNone
			run.appendResult(&res)
			emitResult(d, run, res)
			return
		}

		applyFingerprint(&res, sent)
		body := bodyOf(sent.RespRaw)

		switch {
		case apispec.LooksLikeChallenge(body):
			res.BodyKind = apispec.KindChallenge
			if run.noteChallenge() {
				halt("the target is answering with a bot-check interstitial; further requests would learn nothing")
			}
		case apispec.ShouldSkipContentType(res.ContentType):
			res.BodyKind = apispec.KindSkip
		default:
			res.BodyKind = classify(body, res.ContentType, target, run, d, onSpec, &res)
		}

		run.appendResult(&res)
		emitResult(d, run, res)

		// Follow references out of a UI page or an initializer.
		if depth < MaxFollowDepth && (res.BodyKind == apispec.KindReference || res.BodyKind == apispec.KindNone) {
			for _, ref := range apispec.ExtractSpecRefs(body, target) {
				// Same-host only, and that is the whole guard. A reference
				// off-origin is a scope escape, not a discovery — including the
				// public sample document Swagger UI ships as its stock default,
				// which is the case a separate demo-host filter used to catch.
				// Such a filter is worse than redundant here: it can only ever be
				// reached by a same-origin reference, so the one time it fires is
				// when the operator is deliberately sweeping a sample host, and it
				// refuses to follow that host's own initializer.
				if !apispec.SameHost(ref, origin) {
					continue
				}
				if !claimFollow(ref) {
					continue
				}
				probe(ref, depth+1)
			}
		}
	}

	work := make(chan string, conc)
	var wg sync.WaitGroup
	for range conc {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range work {
				if limiter != nil {
					select {
					case <-runCtx.Done():
						return
					case <-limiter:
					}
				}
				if runCtx.Err() != nil {
					return
				}
				probe(target, 0)
				if cfg.StopOnFirst {
					if _, _, _, hits := run.Counts(); hits > 0 {
						cancel()
						return
					}
				}
			}
		}()
	}

	for _, p := range paths {
		full := origin + p
		seenMu.Lock()
		dup := seen[full]
		seen[full] = true
		seenMu.Unlock()
		if dup {
			continue
		}
		select {
		case work <- full:
		case <-runCtx.Done():
		}
		if runCtx.Err() != nil {
			break
		}
	}
	close(work)
	wg.Wait()

	if stopped {
		run.finish(StatusStopped)
	}
	finishRun(d, run, start)
}

// classify decides what one discovery response turned out to be, loading any
// document it finds.
func classify(
	body []byte, contentType, target string, run *Run, d Deps,
	onSpec func(*apispec.Spec, []byte), res *Result,
) apispec.BodyKind {
	if res.Status < 200 || res.Status >= 400 || len(body) == 0 {
		return apispec.KindNone
	}

	isHTML := strings.Contains(strings.ToLower(contentType), "text/html") || apispec.LooksLikeHTMLDocument(body)
	if isHTML {
		return apispec.KindReference
	}

	candidate := body
	isJS := strings.Contains(strings.ToLower(contentType), "javascript") ||
		strings.HasSuffix(strings.ToLower(pathOf(target)), ".js")
	if isJS {
		if !apispec.LooksLikeSwaggerInit(target) {
			return apispec.KindSkip
		}
		unwrapped, ok := apispec.UnwrapJSSpec(body)
		if !ok {
			return apispec.KindReference
		}
		candidate = unwrapped
	}

	// Default placeholders, deliberately: a sweep parses a candidate only to
	// report its title and operation count, neither of which depends on a
	// generated value. The operator sets placeholders on the document once it is
	// the one they are working, which re-parses it.
	spec, err := apispec.ParseOpenAPI(candidate, apispec.Options{SourceURL: target})
	if err != nil {
		// Document-shaped but unparseable is still worth surfacing: it is
		// frequently a truncated or auth-gated document, and the operator can
		// judge. sj discards these silently.
		if looksDocumentShaped(candidate) {
			return apispec.KindWeak
		}
		return apispec.KindNone
	}
	if len(spec.Operations) == 0 {
		return apispec.KindWeak
	}

	res.SpecTitle = spec.Title
	res.SpecFormat = string(spec.Format)
	res.SpecOps = len(spec.Operations)
	if onSpec != nil {
		onSpec(spec, candidate)
	}
	return apispec.KindSpec
}

// looksDocumentShaped reports whether bytes mention a version token at all, so a
// near-miss can be told from an unrelated 200.
func looksDocumentShaped(body []byte) bool {
	window := body
	if len(window) > 4096 {
		window = window[:4096]
	}
	s := strings.ToLower(string(window))
	return strings.Contains(s, "\"swagger\"") || strings.Contains(s, "\"openapi\"") ||
		strings.Contains(s, "swagger:") || strings.Contains(s, "openapi:")
}

// bodyOf splits the body out of a raw response.
func bodyOf(raw []byte) []byte {
	if i := strings.Index(string(raw), "\r\n\r\n"); i >= 0 {
		return raw[i+4:]
	}
	if i := strings.Index(string(raw), "\n\n"); i >= 0 {
		return raw[i+2:]
	}
	return nil
}

func pathOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return "/"
	}
	// EscapedPath, not Path: url.Parse percent-decodes into Path, and a followed
	// reference carrying %0d%0a would come back as a real CRLF — straight into
	// the request line below.
	p := u.EscapedPath()
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	for i := 0; i < len(p); i++ {
		if p[i] <= 0x20 || p[i] >= 0x7f {
			return "/"
		}
	}
	return p
}
