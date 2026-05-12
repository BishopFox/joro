package callback

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/xsshunter"
)

// HTTPServer listens for HTTP requests and records interactions for matching tokens.
type HTTPServer struct {
	store     *Store
	xssStore  *xsshunter.Store
	broadcast chan<- any
	bindAddr  string
	port      int
	srv       *http.Server
	httpsPort int
	httpsSrv  *http.Server
}

// NewHTTPServer creates an HTTP callback server.
func NewHTTPServer(store *Store, xssStore *xsshunter.Store, broadcast chan<- any, bindAddr string, port int) *HTTPServer {
	s := &HTTPServer{
		store:     store,
		xssStore:  xssStore,
		broadcast: broadcast,
		bindAddr:  bindAddr,
		port:      port,
	}
	s.srv = &http.Server{
		Addr:              fmt.Sprintf("%s:%d", bindAddr, port),
		Handler:           http.HandlerFunc(s.handle),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s
}

// WithTLS configures a parallel HTTPS listener on the given port.
func (h *HTTPServer) WithTLS(tlsCfg *tls.Config, port int) {
	h.httpsPort = port
	h.httpsSrv = &http.Server{
		Addr:              fmt.Sprintf("%s:%d", h.bindAddr, port),
		Handler:           http.HandlerFunc(h.handle),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// Start begins listening. It blocks until ctx is cancelled.
func (h *HTTPServer) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		h.srv.Shutdown(shutCtx) //nolint:errcheck
		if h.httpsSrv != nil {
			h.httpsSrv.Shutdown(shutCtx) //nolint:errcheck
		}
	}()

	if h.httpsSrv != nil {
		go func() {
			if err := h.httpsSrv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				log.Printf("HTTPS callback server: %v", err)
			}
		}()
	}

	if err := h.srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (h *HTTPServer) handle(w http.ResponseWriter, r *http.Request) {
	// Route XSS Hunter paths before token correlation.
	if strings.HasPrefix(r.URL.Path, "/_xss/") {
		h.handleXSS(w, r)
		return
	}

	cfg, _ := h.store.GetConfig()
	domain := cfg.Domain

	host := r.Host
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		host = hostname
	}

	token, err := Correlate(h.store, host, domain)
	if err != nil {
		http.Error(w, "79cb7b990dd6d0d8eac756c92ccc04b6", http.StatusOK)
		return
	}

	sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	// Read body
	bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	r.Body.Close()

	// Dump headers as JSON
	headersJSON, _ := json.Marshal(r.Header)

	// Dump raw request
	rawReq, _ := httputil.DumpRequest(r, false)
	rawFull := append(rawReq, bodyBytes...)

	id := make([]byte, 16)
	rand.Read(id) //nolint:errcheck
	interaction := &Interaction{
		ID:         hex.EncodeToString(id),
		TokenID:    token.ID,
		Token:      token.Token,
		Type:       "http",
		SourceIP:   sourceIP,
		Timestamp:  time.Now().UTC(),
		Method:     r.Method,
		Path:       r.URL.RequestURI(),
		Headers:    string(headersJSON),
		Body:       base64.StdEncoding.EncodeToString(bodyBytes),
		RawRequest: base64.StdEncoding.EncodeToString(rawFull),
	}

	if err := h.store.RecordInteraction(interaction); err != nil {
		log.Printf("callback http: record interaction: %v", err)
	}
	h.broadcast <- event.WSEvent{Type: "callback.interaction", Data: interaction}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "79cb7b990dd6d0d8eac756c92ccc04b6")
}

func (h *HTTPServer) handleXSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/_xss/")

	// POST /_xss/callback — receive XSS fire data.
	if path == "callback" && r.Method == http.MethodPost {
		h.handleXSSCallback(w, r)
		return
	}

	// POST /_xss/page_callback — receive collected page data.
	if path == "page_callback" && r.Method == http.MethodPost {
		h.handleXSSPageCallback(w, r)
		return
	}

	// GET /_xss/html2canvas.min.js — serve embedded html2canvas library.
	if path == "html2canvas.min.js" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(xsshunter.Html2canvasJS)
		return
	}

	// GET /_xss/<probeHex> — serve probe JavaScript.
	if r.Method == http.MethodGet && path != "" {
		h.handleXSSProbeJS(w, r, path)
		return
	}

	http.NotFound(w, r)
}

func (h *HTTPServer) handleXSSProbeJS(w http.ResponseWriter, r *http.Request, probeHex string) {
	if h.xssStore == nil {
		http.NotFound(w, r)
		return
	}

	probe, err := h.xssStore.FindProbeByHex(probeHex)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	cfg, _ := h.store.GetConfig()
	scheme := "http"
	host := r.Host
	port := h.port
	if r.TLS != nil {
		scheme = "https"
		if h.httpsPort > 0 {
			port = h.httpsPort
		}
	}
	if cfg.Domain != "" {
		host = cfg.Domain
		if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
			host = fmt.Sprintf("%s:%d", cfg.Domain, port)
		}
	}
	callbackBase := fmt.Sprintf("%s://%s", scheme, host)

	// Parse per-probe collect pages; fall back to global config.
	var collectPages []string
	if probe.CollectPages != "" {
		json.Unmarshal([]byte(probe.CollectPages), &collectPages) //nolint:errcheck
	}
	if len(collectPages) == 0 {
		if globalPages, _ := h.store.GetConfigValue("xss_collect_pages"); globalPages != "" {
			json.Unmarshal([]byte(globalPages), &collectPages) //nolint:errcheck
		}
	}

	// Per-probe chainload URI; fall back to global config.
	chainloadURI := probe.ChainloadURI
	if chainloadURI == "" {
		chainloadURI, _ = h.store.GetConfigValue("xss_chainload_uri")
	}

	js := xsshunter.ProbeJS(callbackBase, probeHex, collectPages, chainloadURI)

	w.Header().Set("Content-Type", "application/javascript")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, js)
}

func (h *HTTPServer) handleXSSCallback(w http.ResponseWriter, r *http.Request) {
	if h.xssStore == nil {
		http.Error(w, "not configured", http.StatusServiceUnavailable)
		return
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 5<<20)) // 5MB limit
	r.Body.Close()

	var payload struct {
		ProbeID      string `json:"probeId"`
		URL          string `json:"url"`
		Origin       string `json:"origin"`
		Referrer     string `json:"referrer"`
		UserAgent    string `json:"userAgent"`
		Cookies      string `json:"cookies"`
		PageTitle    string `json:"pageTitle"`
		DOM          string `json:"dom"`
		Screenshot   string `json:"screenshot"`
		PageText     string `json:"pageText"`
		InIframe     bool   `json:"inIframe"`
		BrowserTime  string `json:"browserTime"`
		InjectionKey string `json:"injectionKey"`
	}

	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	probe, err := h.xssStore.FindProbeByHex(payload.ProbeID)
	if err != nil {
		http.Error(w, "unknown probe", http.StatusNotFound)
		return
	}

	sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	id := make([]byte, 16)
	rand.Read(id) //nolint:errcheck

	fire := &xsshunter.Fire{
		ID:           hex.EncodeToString(id),
		ProbeID:      probe.ID,
		ProbeToken:   probe.ProbeID,
		URL:          payload.URL,
		Origin:       payload.Origin,
		Referrer:     payload.Referrer,
		UserAgent:    payload.UserAgent,
		Cookies:      payload.Cookies,
		PageTitle:    payload.PageTitle,
		DOM:          payload.DOM,
		Screenshot:   payload.Screenshot,
		PageText:     payload.PageText,
		SourceIP:     sourceIP,
		InIframe:     payload.InIframe,
		BrowserTime:  payload.BrowserTime,
		InjectionKey: payload.InjectionKey,
		FiredAt:      time.Now().UTC(),
	}

	if err := h.xssStore.RecordFire(fire); err != nil {
		log.Printf("xss callback: record fire: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.broadcast <- event.WSEvent{Type: "xss.fire", Data: fire}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"id": fire.ID})
}

func (h *HTTPServer) handleXSSPageCallback(w http.ResponseWriter, r *http.Request) {
	if h.xssStore == nil {
		http.Error(w, "not configured", http.StatusServiceUnavailable)
		return
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 5<<20))
	r.Body.Close()

	var payload struct {
		FireID  string `json:"fireId"`
		ProbeID string `json:"probeId"`
		URL     string `json:"url"`
		HTML    string `json:"html"`
	}

	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Determine fire ID: use provided fireId, or find the most recent fire for this probe.
	fireID := payload.FireID
	if fireID == "" && payload.ProbeID != "" {
		if fire, err := h.xssStore.FindRecentFireByProbeHex(payload.ProbeID); err == nil {
			fireID = fire.ID
		}
	}
	if fireID == "" {
		http.Error(w, "cannot correlate page to fire", http.StatusBadRequest)
		return
	}

	id := make([]byte, 16)
	rand.Read(id) //nolint:errcheck

	page := &xsshunter.CollectedPage{
		ID:          hex.EncodeToString(id),
		FireID:      fireID,
		URL:         payload.URL,
		HTML:        payload.HTML,
		CollectedAt: time.Now().UTC(),
	}

	if err := h.xssStore.RecordCollectedPage(page); err != nil {
		log.Printf("xss page callback: record page: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.broadcast <- event.WSEvent{Type: "xss.page", Data: page}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"id": page.ID})
}
