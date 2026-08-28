package capreg

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/webhook"
)

// The webhook capabilities.
//
// There is no create, edit or delete here, and that absence is the whole safety argument
// rather than an omission to be filled in later. A webhook is an egress channel; authoring one
// is grant administration for it, which is the class of thing internal/capability's reserved
// prefixes exist to keep unreachable. "webhook." is not among those prefixes, so nothing would
// refuse such a capability — it stays out because it is not written, and the control plane in
// internal/api stays UI-only for the same reason the token one does.
//
// What a run gets instead is a *choice among the operator's endpoints*. The id is the only
// address; the URL, the headers and the secrets are not arguments, are not in the result, and
// are not in these schemas. webhook.Store enforces the second half: AllowAutomations is off by
// default, so an endpoint is reachable from a run only because the operator ticked it — the
// same shape as arming a command automation, where the authority is the arming.
//
// SendsTraffic is deliberately false. The scope guard describes web targets, and a
// notification endpoint is not one: hooks.slack.com will never be inside an engagement's
// scope, so guarding this would deny every call rather than bound one, and setting an
// automation's host whitelist to leash it to a target would take its notifications away too.
// caps_privileged.go states the same argument for the C2 capabilities, which reach the
// operator's own server for the same reason. Two consequences of that flag follow and are
// replaced by hand: there is no target in the audit entry, so RecordChange names the webhook
// and the status; and the call is not charged against a run's send budget, so
// webhook.Deliverer keeps a per-principal fire limit of its own.

// WebhookFirer is the fire-only view of the webhook store.
//
// A narrow interface rather than the store itself, following the ScriptRunner precedent: a
// capability body gets "fire this endpoint and tell me what happened" and nothing that could
// resolve, add or edit one. Deps is the documented place where authority leaks into this
// package, so what passes through it should be no larger than the job.
type WebhookFirer interface {
	Fire(ctx context.Context, principal, id, message string, data json.RawMessage) (webhook.FireResult, error)
	List() []webhook.Listed
}

// renderWebhooks lays the list out as a fixed-width table, following the encoding rule in
// render.go: repeated JSON keys are over half the token cost of a row.
func renderWebhooks(list []webhook.Listed) string {
	idW, nameW := 0, 0
	for _, w := range list {
		idW = max(idW, len(w.ID))
		nameW = max(nameW, len(w.Name))
	}
	var b strings.Builder
	b.WriteString(pad("id", idW) + " " + pad("name", nameW) + " state description\n")
	for _, w := range list {
		state := "ready"
		if !w.Enabled {
			state = "off"
		}
		fmt.Fprintf(&b, "%s %s %s %s\n", pad(w.ID, idW), pad(w.Name, nameW),
			pad(state, 5), w.Description)
	}
	return strings.TrimRight(b.String(), "\n")
}

type webhookFireArgs struct {
	ID      string          `json:"id"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func registerWebhook(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:       "webhook.list",
		Class:    capability.ClassWebhook,
		Title:    "List the webhooks you may fire",
		Mutating: false,
		Description: "List the notification endpoints the operator has opened to automation, by id and " +
			"name. Destinations are not returned: where a notification goes is the operator's " +
			"configuration, and you do not need it in order to send one. An endpoint absent here " +
			"cannot be fired, whether or not it exists.",
		InputSchema:    json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		ArgsExample:    json.RawMessage(`{}`),
		MaxOutputBytes: 8 << 10,
		Handler: capability.Typed(func(_ context.Context, _ capability.Principal, _ struct{}) (any, error) {
			if d.Webhooks == nil {
				return nil, fmt.Errorf("webhooks are unavailable on this instance")
			}
			list := d.Webhooks.List()
			if len(list) == 0 {
				return "No webhooks are open to automation. The operator opens one in " +
					"Settings, Webhooks, by allowing automations to fire it.", nil
			}
			return renderWebhooks(list), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:       "webhook.fire",
		Class:    capability.ClassWebhook,
		Title:    "Fire a configured webhook",
		Mutating: true,
		Description: "Send a notification through one of the operator's configured endpoints, named by its " +
			"id from webhook_list. The destination, the headers and any credential are the " +
			"operator's and are not yours to choose — you select among endpoints that already " +
			"exist. The body's shape is the operator's template; your message fills the one slot " +
			"reserved for it. Scope and this token's host whitelist do not apply, because they " +
			"describe web targets and this is the operator's own notification channel. Use it to " +
			"report something worth interrupting a person for, not as a log: firing is rate " +
			"limited, and every call is recorded in the operator's activity log.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "id":      {"type":"string","description":"The webhook to fire, as returned by webhook_list."},
    "message": {"type":"string","description":"One line a person will read in a chat client. Say what happened and where."},
    "data":    {"type":"object","description":"Optional structured detail for a machine receiver. Delivered only when the operator's webhook sends Joro's own envelope; a preset or a custom template ignores it."}
  },
  "required":["id","message"],
  "additionalProperties":false
}`),
		ArgsExample: json.RawMessage(`{"id":"team-slack","message":"Critical: exposed AWS key on api.example.com","data":{"findingId":"f-1842"}}`),
		// Comfortably over the longest per-webhook timeout, so a slow receiver produces its
		// own error rather than the registry's generic one.
		Timeout:        90 * time.Second,
		MaxOutputBytes: 4 << 10,
		Handler: capability.Typed(func(ctx context.Context, p capability.Principal, args webhookFireArgs) (any, error) {
			if d.Webhooks == nil {
				return nil, fmt.Errorf("webhooks are unavailable on this instance")
			}
			res, err := d.Webhooks.Fire(ctx, p.TokenID, args.ID, args.Message, args.Data)
			if err != nil {
				return nil, err
			}
			// The id and the status, never the payload: the audit log is not a second copy of
			// what left the machine.
			capability.RecordChange(ctx, "fire webhook %s (status %d)", res.Webhook, res.Status)
			return fmt.Sprintf("fired %s: status %d in %dms", res.Webhook, res.Status, res.DurationMs), nil
		}),
	})
}
