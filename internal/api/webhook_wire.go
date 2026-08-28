package api

import (
	"context"
	"log"
	"net/http"

	"github.com/BishopFox/joro/internal/capreg"
	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/jsautomation"
	"github.com/BishopFox/joro/internal/proxy"
	"github.com/BishopFox/joro/internal/trigger"
	"github.com/BishopFox/joro/internal/webhook"
)

// Bringing the webhook feature up.
//
// It is deliberately not part of SetAutomation. Automation is an agent surface behind three
// launch flags; a webhook is the operator telling their own team channel that something
// happened, and needing to arm an agent to get one would be a strange price. So the store and
// the dispatcher are built in New, and the only switch is --no-webhooks.

// initTriggers opens the custom trigger store.
//
// It lives here rather than in newScriptManager because two features now reference it, and the
// one that is always available must not depend on the one behind flags. Without this a webhook
// could name only the built-in events on a Joro started without --automation-scripting, and
// the trigger editor would 404.
//
// A file that will not parse disables custom triggers and says so, rather than presenting an
// empty set. The difference matters for both consumers: an empty store would leave every
// automation and every webhook referencing a custom trigger with nothing to resolve, and the
// operator would see them stop firing with no explanation.
func (s *APIServer) initTriggers() {
	if s.listenerMode {
		return
	}
	store, err := trigger.NewStore(s.cfg.DataDir)
	if err != nil {
		log.Printf("[automation] custom triggers are unavailable: %v", err)
		return
	}
	s.triggers = store
}

// initWebhooks opens the webhook store and builds the dispatcher and deliverer.
//
// A failure is non-fatal and disables the feature rather than the proxy, the same way an
// unreadable automation.json does: an operator should still be able to test. It is logged
// loudly, because a silently absent store would look like their webhooks had been deleted.
func (s *APIServer) initWebhooks() {
	if s.listenerMode || s.cfg.NoWebhooks {
		return
	}
	store, err := webhook.NewStore(s.cfg.DataDir, s.triggers)
	if err != nil {
		log.Printf("[webhook] webhooks are disabled this run: %v", err)
		return
	}
	s.webhooks = store
	s.webhookDeliver = webhook.NewDeliverer(store, s.webhookClient,
		s.buildInfo.Version, s.hub.Broadcast())
	s.webhookDispatch = webhook.NewDispatcher(store, s.webhookDeliver)
}

// webhookClient builds the client one delivery uses.
//
// NewOutboundHTTPClient rather than NewHTTPClient: a webhook endpoint is the operator's own
// infrastructure, frequently one whose URL is itself the credential, so its certificate is
// verified. NewHTTPClient's permissive TLS is for targets Joro is already MITM-ing. Both
// configs are built inside internal/proxy, which is the rule that keeps them readable side by
// side.
func (s *APIServer) webhookClient(insecure bool) http.Client {
	return proxy.NewOutboundHTTPClient(s.transport, insecure)
}

// startWebhooks runs the dispatcher and the delivery pump for the life of the server.
//
// The hub subscription is made here for the same reason startScriptTriggers makes its own:
// internal/webhook cannot import this package, so the wiring belongs on this side. It is a
// second subscriber, which Hub.Subscribe already supports — each gets its own channel and its
// own non-blocking send.
func (s *APIServer) startWebhooks(ctx context.Context) {
	if s.webhookDispatch == nil {
		return
	}
	go s.webhookDispatch.Run(ctx, s.hub.Subscribe(0))
	go s.webhookDeliver.Run(ctx)
}

// watchAutomationRuns points the webhook dispatcher at finished automation runs.
//
// automation.completed is the one event in the trigger catalog that never reaches the bus — a
// per-run broadcast would be a firehose an agent controls — so a consumer has to be registered
// with the manager instead. Called from startScriptTriggers, after the trigger dispatcher has
// registered itself; Manager.WatchRuns appends, so both are told.
func (s *APIServer) watchAutomationRuns() {
	if s.webhookDispatch == nil || s.scriptManager == nil {
		return
	}
	s.scriptManager.WatchRuns(&webhookRunWatcher{d: s.webhookDispatch})
}

// webhookRunWatcher hands a finished run to the webhook dispatcher.
//
// It projects through jsautomation.RunRef rather than building its own map, so both watchers
// of this event see byte-identical fields. A second hand-written projection is exactly how a
// condition comes to fire for an automation and not for a webhook watching the same trigger —
// which is the class of bug trigger.Project exists to have one answer to.
type webhookRunWatcher struct{ d *webhook.Dispatcher }

func (w *webhookRunWatcher) RunCompleted(automationID string, run *jsautomation.Run) {
	if run == nil || automationID == "" {
		return
	}
	ref := jsautomation.RunRef(automationID, run)
	if ref == nil {
		return
	}
	w.d.Observe(event.WSEvent{Type: trigger.EventAutomationComplete, Data: ref})
}

// webhookFirer returns the deliverer as the interface capreg expects, or a nil interface when
// webhooks are off. Returning the typed nil pointer directly would give capreg a non-nil
// interface holding nil, and the handler's own nil check would not catch it — the same trap
// scriptRunnerDep avoids.
func (s *APIServer) webhookFirer() capreg.WebhookFirer {
	if s.webhookDeliver == nil {
		return nil
	}
	return s.webhookDeliver
}
