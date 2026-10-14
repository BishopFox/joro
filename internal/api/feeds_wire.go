package api

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/feeds"
	"github.com/BishopFox/joro/internal/proxy"
)

// Bringing the threat-intel feed aggregator up.
//
// Like the webhook feature, it is independent of automation and built in New rather than in
// SetAutomation — an operator wanting CVE and KEV intel on their dashboard should not have to
// arm an agent. The only switches are --no-feeds (removes it) and the off-by-default Settings
// toggle (fetches nothing until armed). internal/feeds imports nothing from this package; the
// outbound client is injected here as feedsFetch, the one place internal/proxy is reached.

// initFeeds opens feeds.json and builds the aggregator over the curated source set.
//
// A failure is non-fatal and disables the feature rather than the proxy, the same way an
// unreadable webhooks.json does, and is logged loudly so a silently absent store does not look
// like the operator's settings vanished.
func (s *APIServer) initFeeds() {
	if s.listenerMode || s.cfg.NoFeeds {
		return
	}
	store, err := feeds.NewSettingsStore(s.cfg.DataDir)
	if err != nil {
		log.Printf("[feeds] threat-intel feeds are disabled this run: %v", err)
		return
	}
	s.feedsStore = store
	s.feeds = feeds.NewAggregator(feeds.DefaultSources(), s.feedsFetch)
}

// feedsFetch is the injected FetchFunc: a verified-TLS (insecure=false), no-redirect GET with
// a request timeout and a bounded read. NewOutboundHTTPClient rather than NewHTTPClient because
// NVD/CISA/ExploitDB/FIRST.org are public infrastructure to be authenticated, not MITM targets.
//
// Direct egress by default: feed traffic is incidental intel, not engagement traffic, so it
// should not consume or reveal the operator's SOCKS tunnel. Passing a nil TransportConfig
// leaves DialContext unset (a direct dial); only when the operator opts in via RouteThroughSocks
// is s.transport passed, which honors SOCKS when one is configured. Built per fetch and closed,
// because the transport snapshots the dialer at build time and has no idle timeout.
func (s *APIServer) feedsFetch(ctx context.Context, rawURL string, limitBytes int64) ([]byte, error) {
	var tc *proxy.TransportConfig
	if s.feedsStore != nil && s.feedsStore.Get().RouteThroughSocks {
		tc = s.transport
	}
	client := proxy.NewOutboundHTTPClient(tc, false)
	defer client.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, application/atom+xml, application/rss+xml, application/xml;q=0.9, */*;q=0.1")
	req.Header.Set("User-Agent", "Joro/"+s.buildInfo.Version)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed endpoint returned HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limitBytes))
}

// startFeedsLoop runs the periodic refresher for the life of the server.
//
// A one-minute ticker is the backstop resolution; the actual cadence is the operator's
// interval (floored at 15 min), tracked by nextRun. The loop no-ops while feeds are disabled
// in settings, so toggling them on takes effect with no restart — and a handler kicks an
// immediate refresh on an enable-flip so the UI does not wait up to a minute. feedsCtx is set
// here, before serving, so a handler-kicked refresh can outlive its request.
func (s *APIServer) startFeedsLoop(ctx context.Context) {
	if s.feeds == nil || s.feedsStore == nil {
		return
	}
	s.feedsCtx = ctx
	go func() {
		// A short settle so startup is not a thundering herd of outbound calls.
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}

		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		var nextRun time.Time // zero => run on the first enabled pass
		for {
			st := s.feedsStore.Get()
			if st.Enabled && (nextRun.IsZero() || !time.Now().Before(nextRun)) {
				s.refreshFeedsTick(ctx)
				nextRun = time.Now().Add(time.Duration(st.IntervalMinutes) * time.Minute)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// refreshFeedsTick refreshes the enabled categories and broadcasts the summary. A no-op when
// feeds are off, so every caller (the loop, the manual-refresh handler, the enable kick) can
// call it unconditionally.
func (s *APIServer) refreshFeedsTick(ctx context.Context) {
	if s.feeds == nil || s.feedsStore == nil {
		return
	}
	st := s.feedsStore.Get()
	if !st.Enabled {
		return
	}
	snap := s.feeds.Refresh(ctx, st.Categories)
	s.hub.Broadcast() <- event.WSEvent{Type: "feeds.updated", Data: feedsSummary(snap)}
}

// feedsContext returns the server-lifetime context for a handler-kicked refresh, falling back
// to Background if the loop never started (it always does in proxy mode when feeds are on).
func (s *APIServer) feedsContext() context.Context {
	if s.feedsCtx != nil {
		return s.feedsCtx
	}
	return context.Background()
}

// feedsSummaryData is the small, droppable hint pushed on feeds.updated. The client re-GETs
// the authoritative snapshot, the same pattern tech.detected / detect.summary use.
type feedsSummaryData struct {
	GeneratedAt time.Time      `json:"generatedAt"`
	Counts      map[string]int `json:"counts"`
	AnyStale    bool           `json:"anyStale"`
}

func feedsSummary(snap feeds.Snapshot) feedsSummaryData {
	counts := make(map[string]int, len(snap.Items))
	for cat, list := range snap.Items {
		counts[string(cat)] = len(list)
	}
	anyStale := false
	for _, src := range snap.Sources {
		if src.Stale {
			anyStale = true
			break
		}
	}
	return feedsSummaryData{GeneratedAt: snap.GeneratedAt, Counts: counts, AnyStale: anyStale}
}
