package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/BishopFox/joro/internal/trigger"
	"github.com/BishopFox/joro/internal/webhook"
)

// The webhook control plane.
//
// UI-only, like the token and trigger planes, and here that is the load-bearing half of the
// feature rather than a convention. A webhook is an egress channel; creating one is deciding
// where Joro's bytes may go, which is administration for it. capreg.Deps holds no webhook
// store — only the fire-only interface — and an automation client reaches Joro on the MCP
// port, whose mux has no /api/v1/* routes at all. Between them there is no path from a token
// to this block.
//
// Secrets go out empty and come back empty. The store carries forward what the client did not
// resend, so a plain round trip cannot wipe a signing key the operator can no longer see.

// requireWebhooks reports whether the webhook store is available, writing the JSON 404 if not.
//
// Two ways to be off, and the message names which: --no-webhooks is a deployment posture, an
// unreadable webhooks.json is a fault. An operator sent to the wrong one has been told
// something worse than nothing.
//
// It returns a JSON 404 rather than being left unregistered, because an unregistered route
// falls through to the SPA catch-all and answers 200 with a page of HTML.
func (s *APIServer) requireWebhooks(w http.ResponseWriter) *webhook.Store {
	if s.cfg.NoWebhooks {
		writeError(w, http.StatusNotFound,
			"webhooks are disabled on this instance; it was started with --no-webhooks")
		return nil
	}
	if s.webhooks == nil {
		writeError(w, http.StatusNotFound,
			"webhooks are unavailable on this instance; see the startup log for why "+
				"~/.joro/webhooks.json could not be read")
		return nil
	}
	return s.webhooks
}

// webhookRow is one webhook as the API returns it: no secret values, and a note of which are
// set so the editor can show a field as filled without ever holding what fills it.
type webhookRow struct {
	webhook.Webhook

	HasAuthSecret    bool `json:"hasAuthSecret"`
	HasSigningSecret bool `json:"hasSigningSecret"`

	// SecretHeaders names the custom headers that have a stored value. A list rather than a
	// flag on Header, so nothing about presentation ends up in webhooks.json.
	SecretHeaders []string `json:"secretHeaders"`
}

// redact strips every secret out of a webhook on the way to the client.
func redactWebhook(w webhook.Webhook) webhookRow {
	row := webhookRow{
		HasAuthSecret:    w.Auth.Token != "",
		HasSigningSecret: w.Signing.Secret != "",
		SecretHeaders:    []string{},
	}
	w.Auth.Token = ""
	w.Signing.Secret = ""

	headers := make([]webhook.Header, len(w.Headers))
	for i, h := range w.Headers {
		if h.Value != "" {
			row.SecretHeaders = append(row.SecretHeaders, h.Name)
		}
		headers[i] = webhook.Header{Name: h.Name}
	}
	w.Headers = headers

	row.Webhook = w
	return row
}

func (s *APIServer) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	store := s.requireWebhooks(w)
	if store == nil {
		return
	}
	all := store.List()
	rows := make([]webhookRow, 0, len(all))
	for _, hook := range all {
		rows = append(rows, redactWebhook(hook))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"webhooks": rows,

		// The authoring vocabulary, served rather than restated in the frontend for the
		// reason the trigger and command vocabularies are: a format or a placeholder added
		// in Go appears in the editor with no client change, and the client can never offer
		// something the server would refuse.
		"formats":    webhook.Formats,
		"deliveries": webhook.Deliveries,
		"authKinds":  webhook.AuthKinds,
		"methods":    webhook.Methods,
		"tokens":     webhook.ReservedTokens(),
		"fields":     webhook.SubstitutableFields(dispatchedEvents()),
		"limits": map[string]int{
			"webhooks":      webhook.MaxWebhooks,
			"triggers":      webhook.MaxTriggerRefs,
			"headers":       webhook.MaxHeaders,
			"templateBytes": webhook.MaxTemplateLen,
			"timeoutMs":     webhook.MaxTimeoutMs,
			"retries":       webhook.MaxRetries,
			"minIntervalMs": webhook.MaxMinIntervalMs,
		},
	})
}

// dispatchedEvents lists the events a webhook can actually watch.
//
// Filtered rather than trigger.Events wholesale: manual and request.selected are started by
// hand, so offering either would be a switch that does nothing.
func dispatchedEvents() []string {
	var out []string
	for _, e := range trigger.Events {
		if trigger.Dispatched(e) {
			out = append(out, e)
		}
	}
	return out
}

func (s *APIServer) handleGetWebhook(w http.ResponseWriter, r *http.Request) {
	store := s.requireWebhooks(w)
	if store == nil {
		return
	}
	hook, err := store.Get(r.PathValue("id"))
	if err != nil {
		writeWebhookError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, redactWebhook(hook))
}

func (s *APIServer) handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	store := s.requireWebhooks(w)
	if store == nil {
		return
	}
	var body webhook.Webhook
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := store.Create(body)
	if err != nil {
		writeWebhookError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, redactWebhook(created))
}

func (s *APIServer) handleUpdateWebhook(w http.ResponseWriter, r *http.Request) {
	store := s.requireWebhooks(w)
	if store == nil {
		return
	}
	var body webhook.Webhook
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := store.Update(r.PathValue("id"), body)
	if err != nil {
		writeWebhookError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, redactWebhook(updated))
}

func (s *APIServer) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	store := s.requireWebhooks(w)
	if store == nil {
		return
	}
	id := r.PathValue("id")
	if err := store.Delete(id); err != nil {
		writeWebhookError(w, err)
		return
	}
	s.webhookDeliver.Forget(id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleSetWebhookEnabled is the rail's per-row switch.
//
// Switching one on also clears a pause, because that is what an operator means by turning a
// tripped webhook back on. Leaving Paused set would make the switch appear to do nothing.
func (s *APIServer) handleSetWebhookEnabled(w http.ResponseWriter, r *http.Request) {
	store := s.requireWebhooks(w)
	if store == nil {
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := store.SetState(r.PathValue("id"), func(hook *webhook.Webhook) {
		hook.Enabled = body.Enabled
		if body.Enabled {
			hook.Paused, hook.PausedReason = false, ""
		}
	})
	if err != nil {
		writeWebhookError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, redactWebhook(updated))
}

// handleTestWebhook renders a sample event and delivers it.
//
// A real request to the real endpoint, not a preview. What an operator gets wrong is the
// destination, the auth and the body shape, and only sending finds all three — so the response
// carries the exact bytes sent alongside what came back.
//
// A delivery that the endpoint rejects is a 200 carrying the status and the error, not an HTTP
// error: the request was well-formed and the answer is about the endpoint, which is what the
// editor renders either way.
func (s *APIServer) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	if s.requireWebhooks(w) == nil {
		return
	}
	// Bounded independently of the webhook's own timeout, so a receiver that accepts the
	// connection and never answers cannot hold an operator's request open.
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	res, err := s.webhookDeliver.Test(ctx, r.PathValue("id"))
	if err != nil {
		writeWebhookError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *APIServer) handleListWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	if s.requireWebhooks(w) == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"deliveries": s.webhookDeliver.Log(r.PathValue("id")),
	})
}

func writeWebhookError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, webhook.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such webhook")
	case errors.Is(err, webhook.ErrExists):
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}
