package fuzzer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/proxy"
)

// FilterType enumerates the criteria for matchers and filters.
type FilterType string

const (
	FilterStatus    FilterType = "status"
	FilterSize      FilterType = "size"
	FilterWordCount FilterType = "words"
	FilterLineCount FilterType = "lines"
	FilterRegex     FilterType = "regex"
)

// AttackMode determines how multiple positions and wordlists are combined.
type AttackMode string

const (
	AttackSpray AttackMode = "spray" // Same payload in all positions
	AttackSplit AttackMode = "split" // Parallel iteration (row by row)
	AttackYolo  AttackMode = "yolo"  // Cartesian product of all combinations
)

var positionRegex = regexp.MustCompile(`FUZZ(\d+)`)

// DetectPositions scans raw request bytes and returns sorted unique position
// labels found (e.g., ["FUZZ1", "FUZZ2"]). If none found but "FUZZ" exists,
// returns ["FUZZ"] for single-position mode.
func DetectPositions(raw []byte) []string {
	matches := positionRegex.FindAll(raw, -1)
	seen := make(map[string]struct{})
	for _, m := range matches {
		seen[string(m)] = struct{}{}
	}
	if len(seen) > 0 {
		positions := make([]string, 0, len(seen))
		for p := range seen {
			positions = append(positions, p)
		}
		sort.Slice(positions, func(i, j int) bool {
			ni, _ := strconv.Atoi(positions[i][4:])
			nj, _ := strconv.Atoi(positions[j][4:])
			return ni < nj
		})
		return positions
	}
	if bytes.Contains(raw, []byte("FUZZ")) {
		return []string{"FUZZ"}
	}
	return nil
}

// Matcher selects results to include in output (whitelist).
type Matcher struct {
	Type  FilterType `json:"type"`
	Value string     `json:"value"`
}

// Filter removes matching results from output (blacklist).
type Filter struct {
	Type  FilterType `json:"type"`
	Value string     `json:"value"`
}

// Config holds the parameters for a fuzzer campaign.
type Config struct {
	RawRequest          []byte
	Scheme              string
	Host                string
	Wordlist            []string            // Single-position wordlist
	Wordlists           map[string][]string // Multi-position: position label → wordlist
	Positions           []string            // Ordered position labels (e.g., ["FUZZ1", "FUZZ2"])
	AttackMode          AttackMode          // spray, split, yolo
	Threads             int
	RateLimit           float64
	FollowRedirects     bool
	UpdateContentLength bool
	FuzzKeyword         string
	Matchers            []Matcher
	Filters             []Filter
	MatcherMode         string // "or" (default) or "and"
	FilterMode          string // "or" (default) or "and"
	MaxStoredBodies     int    // Max results to store full req/resp for (0 = unlimited)
}

// Result holds the outcome of a single fuzz request.
type Result struct {
	Index      int               `json:"index"`
	Payload    string            `json:"payload"`
	Payloads   map[string]string `json:"payloads,omitempty"` // Multi-position: position → payload
	StatusCode int               `json:"statusCode"`
	Size       int               `json:"size"`
	Words      int               `json:"words"`
	Lines      int               `json:"lines"`
	DurationMs int64             `json:"durationMs"`
	URL        string            `json:"url"`
	Error      string            `json:"error,omitempty"`
	Matched    bool              `json:"matched"`
	Filtered   bool              `json:"filtered"`
	ReqRaw     []byte            `json:"-"` // Raw HTTP request bytes (excluded from WS/list JSON)
	RespRaw    []byte            `json:"-"` // Raw HTTP response bytes (excluded from WS/list JSON)
}

// CampaignStatus represents the lifecycle state of a campaign.
type CampaignStatus string

const (
	StatusRunning  CampaignStatus = "running"
	StatusStopped  CampaignStatus = "stopped"
	StatusComplete CampaignStatus = "complete"
)

// Campaign is a running or completed fuzzer campaign.
type Campaign struct {
	ID        string         `json:"id"`
	Status    CampaignStatus `json:"status"`
	CreatedAt time.Time      `json:"createdAt"`
	Config    Config         `json:"-"`
	Total     int            `json:"total"`
	Completed int64          `json:"completed"`
	Errors    int64          `json:"errors"`

	mu              sync.RWMutex
	results         []Result
	cancel          context.CancelFunc
	storedBodies    int64 // atomic: number of results with stored req/resp
	maxStoredBodies int64 // max results to store bodies for
}

// Results returns a copy of the current results slice.
func (c *Campaign) Results() []Result {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Result, len(c.results))
	copy(out, c.results)
	return out
}

// GetResult returns a result by its Index field, or false if not found.
func (c *Campaign) GetResult(index int) (Result, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, r := range c.results {
		if r.Index == index {
			return r, true
		}
	}
	return Result{}, false
}

// ResultsPage returns a paginated slice of results.
func (c *Campaign) ResultsPage(offset, limit int) ([]Result, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	total := len(c.results)
	if offset >= total {
		return nil, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := make([]Result, end-offset)
	copy(page, c.results[offset:end])
	return page, total
}

// Cancel stops the campaign.
func (c *Campaign) Cancel() {
	if c.cancel != nil {
		c.cancel()
	}
}

// GenerateID returns a random 32-char hex string.
func GenerateID() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

// CalcTotal returns the number of requests a campaign will generate.
func CalcTotal(cfg Config) int {
	if len(cfg.Positions) <= 1 {
		return len(cfg.Wordlist)
	}
	switch cfg.AttackMode {
	case AttackSpray:
		if wl, ok := cfg.Wordlists[cfg.Positions[0]]; ok {
			return len(wl)
		}
		return len(cfg.Wordlist)
	case AttackSplit:
		minLen := len(cfg.Wordlists[cfg.Positions[0]])
		for _, pos := range cfg.Positions[1:] {
			if l := len(cfg.Wordlists[pos]); l < minLen {
				minLen = l
			}
		}
		return minLen
	case AttackYolo:
		product := 1
		for _, pos := range cfg.Positions {
			product *= len(cfg.Wordlists[pos])
		}
		return product
	}
	return 0
}

// NewCampaign creates a campaign ready to run.
func NewCampaign(cfg Config, cancel context.CancelFunc) *Campaign {
	total := CalcTotal(cfg)
	maxBodies := int64(cfg.MaxStoredBodies)
	if maxBodies <= 0 {
		maxBodies = 1000 // default
	}
	return &Campaign{
		ID:              GenerateID(),
		Status:          StatusRunning,
		CreatedAt:       time.Now().UTC(),
		Config:          cfg,
		Total:           total,
		results:         make([]Result, 0, total),
		cancel:          cancel,
		maxStoredBodies: maxBodies,
	}
}

type workItem struct {
	index    int
	payloads map[string]string // position label → payload value
}

// Run executes the fuzzer campaign. It blocks until all payloads are processed or ctx is cancelled.
func Run(ctx context.Context, campaign *Campaign, transport *proxy.TransportConfig, broadcast chan<- any) {
	cfg := campaign.Config

	h2Cache := proxy.NewH2TransportCache(transport)
	defer h2Cache.Close()

	// Rate limiter
	var limiter <-chan time.Time
	if cfg.RateLimit > 0 {
		ticker := time.NewTicker(time.Duration(float64(time.Second) / cfg.RateLimit))
		defer ticker.Stop()
		limiter = ticker.C
	}

	work := make(chan workItem, cfg.Threads)

	// Pre-compile regexes for matchers/filters
	matcherRegexes := compileRegexes(cfg.Matchers)
	filterRegexes := compileFilterRegexes(cfg.Filters)

	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range work {
				if limiter != nil {
					select {
					case <-ctx.Done():
						return
					case <-limiter:
					}
				}

				storeBody := atomic.LoadInt64(&campaign.storedBodies) < campaign.maxStoredBodies
				result := executePayload(ctx, transport, h2Cache, cfg, item.index, item.payloads, storeBody)
				if storeBody && result.ReqRaw != nil {
					atomic.AddInt64(&campaign.storedBodies, 1)
				}
				result.Matched = applyMatchers(result, cfg.Matchers, cfg.MatcherMode, matcherRegexes)
				result.Filtered = applyFilters(result, cfg.Filters, cfg.FilterMode, filterRegexes)

				campaign.mu.Lock()
				campaign.results = append(campaign.results, result)
				campaign.mu.Unlock()
				atomic.AddInt64(&campaign.Completed, 1)
				if result.Error != "" {
					atomic.AddInt64(&campaign.Errors, 1)
				}

				broadcast <- event.WSEvent{
					Type: "fuzzer.result",
					Data: map[string]any{
						"campaignId": campaign.ID,
						"result":     result,
					},
				}
			}
		}()
	}

	// Producer: generates work items based on attack mode
	go func() {
		defer close(work)
		produceWorkItems(ctx, cfg, work)
	}()

	wg.Wait()

	campaign.mu.Lock()
	if ctx.Err() != nil {
		campaign.Status = StatusStopped
	} else {
		campaign.Status = StatusComplete
	}
	campaign.mu.Unlock()

	broadcast <- event.WSEvent{
		Type: "fuzzer.complete",
		Data: map[string]any{
			"campaignId": campaign.ID,
			"status":     string(campaign.Status),
			"completed":  atomic.LoadInt64(&campaign.Completed),
			"errors":     atomic.LoadInt64(&campaign.Errors),
		},
	}
}

// produceWorkItems generates work items based on the attack mode and sends them to the work channel.
func produceWorkItems(ctx context.Context, cfg Config, work chan<- workItem) {
	// Single-position mode
	if len(cfg.Positions) <= 1 {
		keyword := cfg.FuzzKeyword
		if keyword == "" {
			keyword = "FUZZ"
		}
		for i, payload := range cfg.Wordlist {
			select {
			case <-ctx.Done():
				return
			case work <- workItem{index: i, payloads: map[string]string{keyword: payload}}:
			}
		}
		return
	}

	// Multi-position modes
	switch cfg.AttackMode {
	case AttackSpray:
		// Same payload in all positions simultaneously
		wl := cfg.Wordlists[cfg.Positions[0]]
		for i, payload := range wl {
			payloads := make(map[string]string, len(cfg.Positions))
			for _, pos := range cfg.Positions {
				payloads[pos] = payload
			}
			select {
			case <-ctx.Done():
				return
			case work <- workItem{index: i, payloads: payloads}:
			}
		}

	case AttackSplit:
		// Parallel iteration: row by row across all wordlists
		total := CalcTotal(cfg)
		for i := 0; i < total; i++ {
			payloads := make(map[string]string, len(cfg.Positions))
			for _, pos := range cfg.Positions {
				payloads[pos] = cfg.Wordlists[pos][i]
			}
			select {
			case <-ctx.Done():
				return
			case work <- workItem{index: i, payloads: payloads}:
			}
		}

	case AttackYolo:
		// Cartesian product: odometer-style index array
		indices := make([]int, len(cfg.Positions))
		itemIndex := 0
		for {
			payloads := make(map[string]string, len(cfg.Positions))
			for j, pos := range cfg.Positions {
				payloads[pos] = cfg.Wordlists[pos][indices[j]]
			}

			select {
			case <-ctx.Done():
				return
			case work <- workItem{index: itemIndex, payloads: payloads}:
			}
			itemIndex++

			// Increment rightmost position first (odometer style)
			carry := true
			for j := len(indices) - 1; j >= 0 && carry; j-- {
				indices[j]++
				if indices[j] < len(cfg.Wordlists[cfg.Positions[j]]) {
					carry = false
				} else {
					indices[j] = 0
				}
			}
			if carry {
				break // all combinations exhausted
			}
		}
	}
}

func executePayload(ctx context.Context, tc *proxy.TransportConfig, h2Cache *proxy.H2TransportCache, cfg Config, index int, payloads map[string]string, storeBody bool) Result {
	// Build display payload string
	result := Result{
		Index: index,
	}
	if len(payloads) == 1 {
		for _, v := range payloads {
			result.Payload = v
		}
	} else {
		// Multi-position: pipe-delimited in position order, include Payloads map
		parts := make([]string, 0, len(cfg.Positions))
		for _, pos := range cfg.Positions {
			parts = append(parts, payloads[pos])
		}
		result.Payload = strings.Join(parts, " | ")
		result.Payloads = payloads
	}

	// Apply replacements: sort positions by label length descending to avoid
	// FUZZ1 matching inside FUZZ10.
	sortedPositions := make([]string, 0, len(payloads))
	for pos := range payloads {
		sortedPositions = append(sortedPositions, pos)
	}
	sort.Slice(sortedPositions, func(i, j int) bool {
		return len(sortedPositions[i]) > len(sortedPositions[j])
	})

	mutated := make([]byte, len(cfg.RawRequest))
	copy(mutated, cfg.RawRequest)
	for _, pos := range sortedPositions {
		mutated = bytes.ReplaceAll(mutated, []byte(pos), []byte(payloads[pos]))
	}

	if cfg.UpdateContentLength {
		mutated = proxy.UpdateContentLength(mutated)
	}

	scheme := cfg.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := cfg.Host
	result.URL = buildResultURL(scheme, host, mutated)

	sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	opts := proxy.SendOptions{
		FollowRedirects: cfg.FollowRedirects,
		Decompress:      true,
		H2Transport:     h2Cache.Get(host),
	}

	start := time.Now()
	res, err := proxy.SendRawRequest(sendCtx, mutated, scheme, host, opts, tc)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		result.DurationMs = time.Since(start).Milliseconds()
		if storeBody {
			result.ReqRaw = mutated
		}
		return result
	}
	defer res.Response.Body.Close()
	result.DurationMs = res.Duration.Milliseconds()
	result.StatusCode = res.Response.StatusCode

	body, err := io.ReadAll(io.LimitReader(res.Response.Body, 10<<20))
	if err != nil {
		result.Error = fmt.Sprintf("read body: %v", err)
		return result
	}

	result.Size = len(body)
	result.Words = countWords(body)
	result.Lines = countLines(body)

	if storeBody {
		result.ReqRaw = mutated
		result.RespRaw = res.RawResp
	}

	return result
}

// buildResultURL composes a display URL from the scheme, host, and the path in
// the raw request line. If host is empty, it extracts the Host header from raw.
func buildResultURL(scheme, host string, raw []byte) string {
	end := bytes.IndexAny(raw, "\r\n")
	if end < 0 {
		end = len(raw)
	}
	parts := bytes.Fields(raw[:end])
	path := "/"
	if len(parts) >= 2 {
		path = string(parts[1])
	}
	if host == "" {
		host = hostHeaderFromRaw(raw)
	}
	return scheme + "://" + host + path
}

func hostHeaderFromRaw(raw []byte) string {
	headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		headerEnd = bytes.Index(raw, []byte("\n\n"))
		if headerEnd < 0 {
			return ""
		}
	}
	headers := bytes.ReplaceAll(raw[:headerEnd], []byte("\r\n"), []byte("\n"))
	for _, line := range bytes.Split(headers, []byte("\n")) {
		if i := bytes.IndexByte(line, ':'); i > 0 {
			if strings.EqualFold(string(line[:i]), "Host") {
				return strings.TrimSpace(string(line[i+1:]))
			}
		}
	}
	return ""
}

func countWords(b []byte) int {
	return len(bytes.Fields(b))
}

func countLines(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	return bytes.Count(b, []byte("\n")) + 1
}

// compileRegexes pre-compiles regex matchers.
func compileRegexes(matchers []Matcher) map[int]*regexp.Regexp {
	regexes := make(map[int]*regexp.Regexp)
	for i, m := range matchers {
		if m.Type == FilterRegex {
			if re, err := regexp.Compile(m.Value); err == nil {
				regexes[i] = re
			}
		}
	}
	return regexes
}

func compileFilterRegexes(filters []Filter) map[int]*regexp.Regexp {
	regexes := make(map[int]*regexp.Regexp)
	for i, f := range filters {
		if f.Type == FilterRegex {
			if re, err := regexp.Compile(f.Value); err == nil {
				regexes[i] = re
			}
		}
	}
	return regexes
}

func applyMatchers(r Result, matchers []Matcher, mode string, regexes map[int]*regexp.Regexp) bool {
	if len(matchers) == 0 {
		return true // no matchers = match all
	}
	if mode == "" {
		mode = "or"
	}
	for i, m := range matchers {
		hit := matchesRule(r, m.Type, m.Value, regexes[i])
		if mode == "or" && hit {
			return true
		}
		if mode == "and" && !hit {
			return false
		}
	}
	return mode == "and" // "and": all matched; "or": none matched
}

func applyFilters(r Result, filters []Filter, mode string, regexes map[int]*regexp.Regexp) bool {
	if len(filters) == 0 {
		return false // no filters = nothing filtered out
	}
	if mode == "" {
		mode = "or"
	}
	for i, f := range filters {
		hit := matchesRule(r, f.Type, f.Value, regexes[i])
		if mode == "or" && hit {
			return true
		}
		if mode == "and" && !hit {
			return false
		}
	}
	return mode == "and"
}

func matchesRule(r Result, ruleType FilterType, value string, compiled *regexp.Regexp) bool {
	switch ruleType {
	case FilterStatus:
		return matchesCSVInt(value, r.StatusCode)
	case FilterSize:
		return matchesCSVInt(value, r.Size)
	case FilterWordCount:
		return matchesCSVInt(value, r.Words)
	case FilterLineCount:
		return matchesCSVInt(value, r.Lines)
	case FilterRegex:
		// Regex is matched against the URL for now (body not stored in result).
		// This is a simplification; a full impl would match against the response body.
		return compiled != nil && compiled.MatchString(r.URL)
	}
	return false
}

func matchesCSVInt(csv string, val int) bool {
	for _, s := range strings.Split(csv, ",") {
		if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && v == val {
			return true
		}
	}
	return false
}
