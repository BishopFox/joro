package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/BishopFox/joro/internal/xsshunter"
)

func (s *APIServer) handleListProbes(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	probes, err := s.xssStore.ListProbes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if probes == nil {
		probes = []xsshunter.Probe{}
	}
	writeJSON(w, http.StatusOK, probes)
}

func (s *APIServer) handleCreateProbe(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	probe, err := xsshunter.GenerateProbe(s.xssStore, body.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, probe)
}

func (s *APIServer) handleDeleteProbe(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	id := r.PathValue("id")
	if err := s.xssStore.DeleteProbe(id); err != nil {
		writeError(w, http.StatusNotFound, "probe not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

func (s *APIServer) handleGetPayloads(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	id := r.PathValue("id")

	probe, err := s.xssStore.FindProbeByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "probe not found")
		return
	}

	cfg, _ := s.cbStore.GetConfig()
	domain := cfg.Domain
	if domain == "" {
		writeError(w, http.StatusBadRequest, "callback domain not configured - set it in the Interact tab")
		return
	}

	// Build the probe URL using the callback HTTP port.
	port := s.cfg.CallbackHTTPPort
	var probeURL string
	if port == 80 {
		probeURL = fmt.Sprintf("http://%s/_xss/%s", domain, probe.ProbeID)
	} else {
		probeURL = fmt.Sprintf("http://%s:%d/_xss/%s", domain, port, probe.ProbeID)
	}

	variants := xsshunter.PayloadVariants(probeURL)

	// Also generate HTTPS payload variants when HTTPS is configured.
	if s.cfg.CallbackHTTPSPort > 0 {
		httpsPort := s.cfg.CallbackHTTPSPort
		var httpsProbeURL string
		if httpsPort == 443 {
			httpsProbeURL = fmt.Sprintf("https://%s/_xss/%s", domain, probe.ProbeID)
		} else {
			httpsProbeURL = fmt.Sprintf("https://%s:%d/_xss/%s", domain, httpsPort, probe.ProbeID)
		}
		variants = append(variants, xsshunter.PayloadVariants(httpsProbeURL)...)
	}

	writeJSON(w, http.StatusOK, variants)
}

func (s *APIServer) handleListFires(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	probeID := r.URL.Query().Get("probe_id")
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}

	items, total, err := s.xssStore.ListFires(probeID, offset, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []xsshunter.FireSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"total":  total,
		"offset": offset,
		"limit":  limit,
	})
}

func (s *APIServer) handleGetFire(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	id := r.PathValue("id")
	fire, err := s.xssStore.GetFire(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "fire not found")
		return
	}
	writeJSON(w, http.StatusOK, fire)
}

func (s *APIServer) handleDeleteFire(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	id := r.PathValue("id")
	if err := s.xssStore.DeleteFire(id); err != nil {
		writeError(w, http.StatusNotFound, "fire not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

func (s *APIServer) handleClearFires(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	probeID := r.URL.Query().Get("probe_id")
	if err := s.xssStore.ClearFires(probeID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

func (s *APIServer) handleUpdateProbe(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	id := r.PathValue("id")

	var body struct {
		CollectPages []string `json:"collectPages"`
		ChainloadURI string   `json:"chainloadUri"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	pagesJSON := "[]"
	if len(body.CollectPages) > 0 {
		if b, err := json.Marshal(body.CollectPages); err == nil {
			pagesJSON = string(b)
		}
	}

	if err := s.xssStore.UpdateProbe(id, pagesJSON, body.ChainloadURI); err != nil {
		writeError(w, http.StatusNotFound, "probe not found")
		return
	}

	probe, err := s.xssStore.FindProbeByID(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, probe)
}

func (s *APIServer) handleListCollectedPages(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	fireID := r.PathValue("id")
	pages, err := s.xssStore.ListCollectedPages(fireID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if pages == nil {
		pages = []xsshunter.CollectedPageSummary{}
	}
	writeJSON(w, http.StatusOK, pages)
}

func (s *APIServer) handleGetCollectedPage(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	id := r.PathValue("id")
	page, err := s.xssStore.GetCollectedPage(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "page not found")
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *APIServer) handleGetXSSConfig(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}

	pagesStr, _ := s.cbStore.GetConfigValue("xss_collect_pages")
	chainloadURI, _ := s.cbStore.GetConfigValue("xss_chainload_uri")

	var pages []string
	if pagesStr != "" {
		json.Unmarshal([]byte(pagesStr), &pages) //nolint:errcheck
	}
	if pages == nil {
		pages = []string{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"collectPages": pages,
		"chainloadUri": chainloadURI,
	})
}

func (s *APIServer) handleUpdateXSSConfig(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}

	var body struct {
		CollectPages []string `json:"collectPages"`
		ChainloadURI string   `json:"chainloadUri"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	pagesJSON := "[]"
	if len(body.CollectPages) > 0 {
		if b, err := json.Marshal(body.CollectPages); err == nil {
			pagesJSON = string(b)
		}
	}

	if err := s.cbStore.SetConfigValue("xss_collect_pages", pagesJSON); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.cbStore.SetConfigValue("xss_chainload_uri", body.ChainloadURI); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"collectPages": body.CollectPages,
		"chainloadUri": body.ChainloadURI,
	})
}
