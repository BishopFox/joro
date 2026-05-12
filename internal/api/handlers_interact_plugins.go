package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/BishopFox/joro/sdk"
)

// providerInfoResponse is the payload for GET /api/v1/plugins/interact-providers.
type providerInfoResponse struct {
	Name         string            `json:"name"`
	Info         sdk.InteractInfo  `json:"info"`
	ConfigSchema []sdk.ConfigField `json:"configSchema"`
}

// handleListInteractProviders lists all loaded InteractProviders with their
// Info() metadata and ConfigSchema() so the UI can render a row per provider.
func (s *APIServer) handleListInteractProviders(w http.ResponseWriter, r *http.Request) {
	if s.pluginManager == nil {
		writeJSON(w, http.StatusOK, []providerInfoResponse{})
		return
	}
	providers := s.pluginManager.InteractProviders()
	out := make([]providerInfoResponse, 0, len(providers))
	for name, ip := range providers {
		out = append(out, providerInfoResponse{
			Name:         name,
			Info:         safeInteractInfo(name, ip),
			ConfigSchema: safeInteractConfigSchema(name, ip),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *APIServer) makeInteractListInstancesHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := s.pluginManager.InteractProviders()[name]
		if ip == nil {
			writeError(w, http.StatusNotFound, "plugin not found")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		instances, err := safeInteractListInstances(name, ip, ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if instances == nil {
			instances = []sdk.InteractInstance{}
		}
		writeJSON(w, http.StatusOK, instances)
	}
}

func (s *APIServer) makeInteractCreateInstanceHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := s.pluginManager.InteractProviders()[name]
		if ip == nil {
			writeError(w, http.StatusNotFound, "plugin not found")
			return
		}
		var config map[string]string
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		inst, err := safeInteractCreateInstance(name, ip, ctx, config)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, inst)
	}
}

func (s *APIServer) makeInteractDeleteInstanceHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := s.pluginManager.InteractProviders()[name]
		if ip == nil {
			writeError(w, http.StatusNotFound, "plugin not found")
			return
		}
		id := r.PathValue("id")
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := safeInteractDeleteInstance(name, ip, ctx, id); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
	}
}

func (s *APIServer) makeInteractSetEnabledHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := s.pluginManager.InteractProviders()[name]
		if ip == nil {
			writeError(w, http.StatusNotFound, "plugin not found")
			return
		}
		id := r.PathValue("id")
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := safeInteractSetEnabled(name, ip, ctx, id, body.Enabled); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"enabled": body.Enabled})
	}
}

func (s *APIServer) makeInteractListInteractionsHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := s.pluginManager.InteractProviders()[name]
		if ip == nil {
			writeError(w, http.StatusNotFound, "plugin not found")
			return
		}
		instanceID := r.URL.Query().Get("instance_id")
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = 50
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		page, err := safeInteractListInteractions(name, ip, ctx, instanceID, offset, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if page.Items == nil {
			page.Items = []sdk.InteractInteraction{}
		}
		writeJSON(w, http.StatusOK, page)
	}
}

func (s *APIServer) makeInteractClearInteractionsHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := s.pluginManager.InteractProviders()[name]
		if ip == nil {
			writeError(w, http.StatusNotFound, "plugin not found")
			return
		}
		instanceID := r.URL.Query().Get("instance_id")
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := safeInteractClearInteractions(name, ip, ctx, instanceID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
	}
}

// ---------------------------------------------------------------------------
// Panic-safe wrappers
// ---------------------------------------------------------------------------

func safeInteractInfo(name string, ip sdk.InteractProvider) (info sdk.InteractInfo) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[plugins] %s: Info panic: %v", name, r)
		}
	}()
	return ip.Info()
}

func safeInteractConfigSchema(name string, ip sdk.InteractProvider) (schema []sdk.ConfigField) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[plugins] %s: ConfigSchema panic: %v", name, r)
			schema = nil
		}
	}()
	return ip.ConfigSchema()
}

func safeInteractListInstances(name string, ip sdk.InteractProvider, ctx context.Context) (out []sdk.InteractInstance, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			log.Printf("[plugins] %s: ListInstances panic: %v", name, r)
		}
	}()
	return ip.ListInstances(ctx)
}

func safeInteractCreateInstance(name string, ip sdk.InteractProvider, ctx context.Context, config map[string]string) (inst sdk.InteractInstance, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			log.Printf("[plugins] %s: CreateInstance panic: %v", name, r)
		}
	}()
	return ip.CreateInstance(ctx, config)
}

func safeInteractDeleteInstance(name string, ip sdk.InteractProvider, ctx context.Context, id string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			log.Printf("[plugins] %s: DeleteInstance panic: %v", name, r)
		}
	}()
	return ip.DeleteInstance(ctx, id)
}

func safeInteractSetEnabled(name string, ip sdk.InteractProvider, ctx context.Context, id string, enabled bool) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			log.Printf("[plugins] %s: SetInstanceEnabled panic: %v", name, r)
		}
	}()
	return ip.SetInstanceEnabled(ctx, id, enabled)
}

func safeInteractListInteractions(name string, ip sdk.InteractProvider, ctx context.Context, instanceID string, offset, limit int) (page sdk.InteractionPage, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			log.Printf("[plugins] %s: ListInteractions panic: %v", name, r)
		}
	}()
	return ip.ListInteractions(ctx, instanceID, offset, limit)
}

func safeInteractClearInteractions(name string, ip sdk.InteractProvider, ctx context.Context, instanceID string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			log.Printf("[plugins] %s: ClearInteractions panic: %v", name, r)
		}
	}()
	return ip.ClearInteractions(ctx, instanceID)
}
