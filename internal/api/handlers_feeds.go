package api

import (
	"net/http"
	"time"

	"github.com/BishopFox/joro/internal/feeds"
)

// The threat-intel feed control plane. UI-only, proxy-mode only.
//
// Routes are registered unconditionally and gated here on requireFeeds, for the same reason
// the webhook and automation planes are: an unregistered route falls through to the SPA
// catch-all and answers 200 with HTML rather than 404 with JSON. There are no secrets to
// redact — a feed snapshot is public intelligence — so unlike webhooks every field goes out
// as stored.

// requireFeeds reports whether the aggregator is available, writing the JSON 404 if not. The
// message names which off-state it is: --no-feeds (a posture) versus an unreadable feeds.json
// (a fault).
func (s *APIServer) requireFeeds(w http.ResponseWriter) *feeds.Aggregator {
	if s.cfg.NoFeeds {
		writeError(w, http.StatusNotFound,
			"threat-intel feeds are disabled on this instance; it was started with --no-feeds")
		return nil
	}
	if s.feeds == nil || s.feedsStore == nil {
		writeError(w, http.StatusNotFound,
			"threat-intel feeds are unavailable on this instance; see the startup log for why "+
				"~/.joro/feeds.json could not be read")
		return nil
	}
	return s.feeds
}

// feedsResponse is the whole feed view: the operator's settings plus the current snapshot.
type feedsResponse struct {
	Settings feeds.State    `json:"settings"`
	Snapshot feeds.Snapshot `json:"snapshot"`
}

// handleGetFeeds returns settings + snapshot. Served even while feeds are disabled (Enabled
// false, empty items), so the UI can render its "enable" state from one call.
func (s *APIServer) handleGetFeeds(w http.ResponseWriter, r *http.Request) {
	agg := s.requireFeeds(w)
	if agg == nil {
		return
	}
	writeJSON(w, http.StatusOK, feedsResponse{
		Settings: s.feedsStore.Get(),
		Snapshot: agg.Snapshot(),
	})
}

func (s *APIServer) handleGetFeedsSettings(w http.ResponseWriter, r *http.Request) {
	if s.requireFeeds(w) == nil {
		return
	}
	writeJSON(w, http.StatusOK, s.feedsStore.Get())
}

// handleSetFeedsSettings validates and persists settings (the store floors the interval), and
// on an off->on flip kicks an immediate refresh so the dashboard fills without waiting for the
// loop's next pass.
func (s *APIServer) handleSetFeedsSettings(w http.ResponseWriter, r *http.Request) {
	if s.requireFeeds(w) == nil {
		return
	}
	var in feeds.State
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	prev := s.feedsStore.Get()
	next, err := s.feedsStore.Set(in)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if next.Enabled && !prev.Enabled {
		go s.refreshFeedsTick(s.feedsContext())
	}
	writeJSON(w, http.StatusOK, next)
}

// handleRefreshFeeds triggers an out-of-band refresh, debounced server-side so a UI button
// cannot push NVD past its rate limit regardless of the client.
func (s *APIServer) handleRefreshFeeds(w http.ResponseWriter, r *http.Request) {
	agg := s.requireFeeds(w)
	if agg == nil {
		return
	}
	if !s.feedsStore.Get().Enabled {
		writeError(w, http.StatusConflict, "threat-intel feeds are turned off; enable them first")
		return
	}
	if !agg.TryBeginManual(60 * time.Second) {
		writeError(w, http.StatusTooManyRequests, "feeds were refreshed moments ago; try again shortly")
		return
	}
	go s.refreshFeedsTick(s.feedsContext())
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "refreshing"})
}
