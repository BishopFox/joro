package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/fuzzer"
)

type fuzzerStartRequest struct {
	Raw                 string              `json:"raw"`
	Scheme              string              `json:"scheme"`
	Host                string              `json:"host"`
	Wordlist            []string            `json:"wordlist"`              // Single-position wordlist
	Wordlists           map[string][]string `json:"wordlists,omitempty"`   // Multi-position: position → wordlist
	AttackMode          string              `json:"attackMode,omitempty"`  // spray, split, yolo
	Threads             int                 `json:"threads"`
	RateLimit           float64             `json:"rateLimit"`
	FollowRedirects     bool                `json:"followRedirects"`
	UpdateContentLength *bool               `json:"updateContentLength,omitempty"`
	FuzzKeyword         string              `json:"fuzzKeyword"`
	Matchers            []fuzzer.Matcher    `json:"matchers"`
	Filters             []fuzzer.Filter     `json:"filters"`
	MatcherMode         string              `json:"matcherMode"`
	FilterMode          string              `json:"filterMode"`
	MaxStoredBodies     int                 `json:"maxStoredBodies,omitempty"`
}

func (s *APIServer) handleFuzzerStart(w http.ResponseWriter, r *http.Request) {
	var req fuzzerStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	rawBytes, err := base64.StdEncoding.DecodeString(req.Raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid raw base64")
		return
	}

	// Detect fuzz positions in the request template
	positions := fuzzer.DetectPositions(rawBytes)
	if len(positions) == 0 {
		// Fallback: check for custom keyword
		keyword := req.FuzzKeyword
		if keyword == "" {
			keyword = "FUZZ"
		}
		if bytes.Contains(rawBytes, []byte(keyword)) {
			positions = []string{keyword}
		} else {
			writeError(w, http.StatusBadRequest, "request template does not contain any FUZZ position markers")
			return
		}
	}

	threads := req.Threads
	if threads < 1 {
		threads = 10
	}
	if threads > 100 {
		threads = 100
	}

	updateCL := req.UpdateContentLength == nil || *req.UpdateContentLength

	cfg := fuzzer.Config{
		RawRequest:          rawBytes,
		Scheme:              req.Scheme,
		Host:                req.Host,
		Positions:           positions,
		Threads:             threads,
		RateLimit:           req.RateLimit,
		FollowRedirects:     req.FollowRedirects,
		UpdateContentLength: updateCL,
		FuzzKeyword:         req.FuzzKeyword,
		Matchers:            req.Matchers,
		Filters:             req.Filters,
		MatcherMode:         req.MatcherMode,
		FilterMode:          req.FilterMode,
		MaxStoredBodies:     req.MaxStoredBodies,
	}

	if len(positions) <= 1 {
		// Single-position mode
		if len(req.Wordlist) == 0 {
			writeError(w, http.StatusBadRequest, "wordlist is empty")
			return
		}
		cfg.Wordlist = req.Wordlist
	} else {
		// Multi-position mode
		mode := fuzzer.AttackMode(req.AttackMode)
		if mode != fuzzer.AttackSpray && mode != fuzzer.AttackSplit && mode != fuzzer.AttackYolo {
			writeError(w, http.StatusBadRequest, "invalid attackMode: must be spray, split, or yolo")
			return
		}
		cfg.AttackMode = mode

		if mode == fuzzer.AttackSpray {
			// Spray: single wordlist used for all positions
			if len(req.Wordlist) == 0 {
				writeError(w, http.StatusBadRequest, "wordlist is empty")
				return
			}
			cfg.Wordlists = make(map[string][]string, len(positions))
			for _, pos := range positions {
				cfg.Wordlists[pos] = req.Wordlist
			}
		} else {
			// Split/Yolo: require a wordlist for each position
			if len(req.Wordlists) == 0 {
				writeError(w, http.StatusBadRequest, "wordlists map is required for split/yolo modes")
				return
			}
			for _, pos := range positions {
				wl, ok := req.Wordlists[pos]
				if !ok || len(wl) == 0 {
					writeError(w, http.StatusBadRequest, fmt.Sprintf("missing or empty wordlist for position %s", pos))
					return
				}
				_ = wl
			}
			cfg.Wordlists = req.Wordlists

			// Safety limit for yolo mode
			if mode == fuzzer.AttackYolo {
				total := fuzzer.CalcTotal(cfg)
				if total > 10_000_000 {
					writeError(w, http.StatusBadRequest, fmt.Sprintf("yolo mode would generate %d requests (max 10,000,000)", total))
					return
				}
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	campaign := fuzzer.NewCampaign(cfg, cancel)
	s.fuzzerStore.Add(campaign)

	go fuzzer.Run(ctx, campaign, s.transport, s.hub.Broadcast())

	s.hub.Broadcast() <- event.WSEvent{
		Type: "fuzzer.started",
		Data: map[string]any{
			"campaignId": campaign.ID,
			"total":      campaign.Total,
		},
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"campaignId": campaign.ID,
		"total":      campaign.Total,
	})
}

func (s *APIServer) handleFuzzerStop(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	campaign := s.fuzzerStore.Get(id)
	if campaign == nil {
		writeError(w, http.StatusNotFound, "campaign not found")
		return
	}
	if campaign.Status != fuzzer.StatusRunning {
		writeError(w, http.StatusConflict, "campaign is not running")
		return
	}
	campaign.Cancel()
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
}

func (s *APIServer) handleFuzzerListCampaigns(w http.ResponseWriter, r *http.Request) {
	campaigns := s.fuzzerStore.List()
	type summary struct {
		ID        string                `json:"id"`
		Status    fuzzer.CampaignStatus `json:"status"`
		CreatedAt string                `json:"createdAt"`
		Total     int                   `json:"total"`
		Completed int64                 `json:"completed"`
		Errors    int64                 `json:"errors"`
	}
	items := make([]summary, 0, len(campaigns))
	for _, c := range campaigns {
		items = append(items, summary{
			ID:        c.ID,
			Status:    c.Status,
			CreatedAt: c.CreatedAt.Format(time.RFC3339),
			Total:     c.Total,
			Completed: atomic.LoadInt64(&c.Completed),
			Errors:    atomic.LoadInt64(&c.Errors),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"campaigns": items})
}

func (s *APIServer) handleFuzzerGetCampaign(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	campaign := s.fuzzerStore.Get(id)
	if campaign == nil {
		writeError(w, http.StatusNotFound, "campaign not found")
		return
	}

	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}

	page, resultTotal := campaign.ResultsPage(offset, limit)
	if page == nil {
		page = []fuzzer.Result{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":          campaign.ID,
		"status":      campaign.Status,
		"createdAt":   campaign.CreatedAt.Format(time.RFC3339),
		"total":       campaign.Total,
		"completed":   atomic.LoadInt64(&campaign.Completed),
		"errors":      atomic.LoadInt64(&campaign.Errors),
		"results":     page,
		"resultTotal": resultTotal,
		"offset":      offset,
		"limit":       limit,
	})
}

func (s *APIServer) handleFuzzerGetResult(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	indexStr := r.PathValue("index")

	campaign := s.fuzzerStore.Get(id)
	if campaign == nil {
		writeError(w, http.StatusNotFound, "campaign not found")
		return
	}

	index, err := strconv.Atoi(indexStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid index")
		return
	}

	result, found := campaign.GetResult(index)
	if !found {
		writeError(w, http.StatusNotFound, "result not found")
		return
	}

	resp := map[string]any{
		"index":      result.Index,
		"payload":    result.Payload,
		"statusCode": result.StatusCode,
		"size":       result.Size,
		"words":      result.Words,
		"lines":      result.Lines,
		"durationMs": result.DurationMs,
		"url":        result.URL,
		"hasBody":    result.ReqRaw != nil,
	}
	if result.Payloads != nil {
		resp["payloads"] = result.Payloads
	}
	if result.Error != "" {
		resp["error"] = result.Error
	}
	if result.ReqRaw != nil {
		resp["reqRaw"] = base64.StdEncoding.EncodeToString(result.ReqRaw)
	}
	if result.RespRaw != nil {
		resp["respRaw"] = base64.StdEncoding.EncodeToString(result.RespRaw)
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleFuzzerDeleteCampaign(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	campaign := s.fuzzerStore.Get(id)
	if campaign == nil {
		writeError(w, http.StatusNotFound, "campaign not found")
		return
	}
	if campaign.Status == fuzzer.StatusRunning {
		writeError(w, http.StatusConflict, "cannot delete a running campaign")
		return
	}
	s.fuzzerStore.Delete(id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *APIServer) handleFuzzerUploadWordlist(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 50<<20) // 50MB limit

	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing file field")
		return
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("reading file: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"lines": lines,
		"count": len(lines),
	})
}
