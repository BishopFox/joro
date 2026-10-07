// Package oast confirms out-of-band interactions by correlating the callback
// server's response hash back into captured traffic. When a target makes a
// server-side request to Joro's callback listener, the listener returns
// sha256(token) (callback.ResponseHash); if that value then appears in traffic
// the proxy captured — reflected into a semi-blind response, say — it is proof
// the interaction actually reached the callback server for that specific probe,
// not a coincidental echo of the injected input.
//
// It is a separate package from internal/detect for the reason internal/anomaly
// is: the detect engine judges one message at a time and its analyzers hold no
// state, but this correlation needs the set of expected hashes, which is derived
// from tokens seen across earlier captures. It is also a separate package from
// internal/callback: the token store lives only in the listener process, while
// captured traffic and detection live only in the proxy process, so the proxy
// side cannot read the token DB and instead harvests tokens from the callback
// hostnames operators injected through the proxy.
//
// Only the results land in detect: this package mints detect.Findings under
// CategoryOOB through detect.FindingID and detect.Store.Upsert — the same path
// internal/anomaly and internal/capreg use — which gives them the Detect table,
// triage, project persistence, the dashboard, triggers and webhooks for free.
// Findings are sticky: a confirmed interaction is evidence, so unlike anomaly's
// outliers they are never retracted.
package oast

import (
	"bytes"
	"context"
	"maps"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/callback"
	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/proxy"
)

// cycleInterval is how often new captures are scanned for reflected hashes.
const cycleInterval = 3 * time.Second

// batchSize bounds one SinceSeq pull.
const batchSize = 500

// ruleID is the synthetic rule identity for these findings. It is not an engine
// rule; detect's RuleEnabledFunc treats an unknown ID as enabled and the finding
// detail carries the explanation.
const ruleID = "oast.reflected"

// Engine scans captured traffic for reflected callback response hashes and mints
// confirmed out-of-band findings into the detect store.
type Engine struct {
	store          *proxy.Store
	findings       *detect.Store
	callbackDomain func() string
	broadcast      chan<- any
	notify         func() // pushes detect.summary after the store changes

	mu     sync.Mutex
	cursor int
	// expected maps a token's response hash to the token hex it was derived from.
	// It accumulates across cycles because a probe and its reflection can be
	// captured in different batches; token counts are small so it never prunes.
	expected map[string]string
}

// NewEngine constructs the engine. callbackDomain is read every cycle so a domain
// learned from the listener after startup takes effect without a restart; an
// empty domain means there is nothing to harvest and the cycle no-ops.
func NewEngine(store *proxy.Store, findings *detect.Store, callbackDomain func() string, broadcast chan<- any, notify func()) *Engine {
	return &Engine{
		store:          store,
		findings:       findings,
		callbackDomain: callbackDomain,
		broadcast:      broadcast,
		notify:         notify,
		expected:       map[string]string{},
	}
}

// Run scans on an interval until ctx is cancelled, mirroring the detect scanner.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(cycleInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.RunCycle()
		}
	}
}

// ResetCursor is called wherever proxy.Store rewrites its sequence numbering
// (Clear zeroes it, a project load rewrites it), the same obligation detect's
// scanner cursor has. It drops the harvested hash set: a rewrite invalidates the
// forward-scan position those were gathered at.
func (e *Engine) ResetCursor(seq int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cursor = seq
	e.expected = map[string]string{}
}

// RunCycle performs one forward-scan pass. Exported so a test or manual trigger
// can drive it without the ticker.
func (e *Engine) RunCycle() {
	if e.store == nil || e.findings == nil {
		return
	}
	domain := ""
	if e.callbackDomain != nil {
		domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(e.callbackDomain())), ".")
	}
	if domain == "" {
		return
	}
	// `<label>.<domain>`, where the token is the first 16 hex of the label.
	hostRe := regexp.MustCompile(`(?i)([0-9a-f]{16})[0-9a-z_-]*\.` + regexp.QuoteMeta(domain))

	e.mu.Lock()
	cursor := e.cursor
	e.mu.Unlock()

	var batch []*proxy.CapturedRequest
	for {
		b := e.store.SinceSeq(cursor, batchSize)
		if len(b) == 0 {
			break
		}
		for _, cr := range b {
			if cr.Seq > cursor {
				cursor = cr.Seq
			}
		}
		batch = append(batch, b...)
		if len(b) < batchSize {
			break
		}
	}
	if len(batch) == 0 {
		return
	}

	// First pass: harvest every callback token injected in this batch so a
	// reflection captured in the same batch is already known.
	e.mu.Lock()
	for _, cr := range batch {
		for _, m := range hostRe.FindAllSubmatch(cr.ReqRaw, -1) {
			tok := strings.ToLower(string(m[1]))
			e.expected[callback.ResponseHash(tok)] = tok
		}
	}
	// Snapshot the hash set for the scan pass.
	expected := make(map[string]string, len(e.expected))
	maps.Copy(expected, e.expected)
	e.mu.Unlock()

	// Second pass: look for any expected hash in the captured bytes.
	changed := false
	if len(expected) > 0 {
		for _, cr := range batch {
			if e.scan(cr, expected) {
				changed = true
			}
		}
	}

	e.mu.Lock()
	e.cursor = cursor
	e.mu.Unlock()

	if changed && e.notify != nil {
		e.notify()
	}
}

// scan checks one capture for a reflected hash and mints a finding on a match.
// Reports whether a new finding was created.
func (e *Engine) scan(cr *proxy.CapturedRequest, expected map[string]string) bool {
	created := false
	for hash, tok := range expected {
		h := []byte(hash)
		// The reflection is almost always in the response; the request is checked
		// too for store-and-forward echoes. A full-SHA-256 match has no realistic
		// false-positive rate, so either location is a confirmed interaction.
		if off := bytes.Index(cr.RespRaw, h); off >= 0 {
			if e.mint(cr, tok, hash, off, "response") {
				created = true
			}
			continue
		}
		if off := bytes.Index(cr.ReqRaw, h); off >= 0 {
			if e.mint(cr, tok, hash, off, "request") {
				created = true
			}
		}
	}
	return created
}

// mint upserts and emits a confirmed out-of-band finding. Identity is keyed on
// the token so repeated reflections of the same probe dedupe to one finding.
func (e *Engine) mint(cr *proxy.CapturedRequest, token, hash string, offset int, part string) bool {
	now := time.Now()
	short := hash
	if len(short) > 16 {
		short = short[:16]
	}
	f := detect.Finding{
		ID:             detect.FindingID(ruleID, cr.Host, token),
		RuleID:         ruleID,
		RuleName:       "Confirmed out-of-band interaction",
		Category:       detect.CategoryOOB,
		Severity:       detect.SeverityHigh,
		Confidence:     detect.ConfidenceHigh,
		Target:         detect.TargetMessage,
		Host:           cr.Host,
		Method:         cr.Method,
		URL:            cr.URL,
		RequestID:      cr.ID,
		Detail:         "token " + token,
		Evidence:       "callback canary " + short + "… reflected in " + part,
		EvidenceOffset: offset,
		EvidenceLength: len(hash),
		EvidencePart:   part,
		FirstSeen:      now,
		LastSeen:       now,
	}
	stored, isNew := e.findings.Upsert(f)
	e.emit(*stored, isNew)
	return isNew
}

func (e *Engine) emit(f detect.Finding, isNew bool) {
	if e.broadcast == nil {
		return
	}
	select {
	case e.broadcast <- event.WSEvent{
		Type: "detect.finding",
		Data: map[string]any{"finding": f, "isNew": isNew},
	}:
	default:
	}
}
