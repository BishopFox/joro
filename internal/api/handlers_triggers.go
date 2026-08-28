package api

import (
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/BishopFox/joro/internal/jsautomation"
	"github.com/BishopFox/joro/internal/trigger"
)

// The trigger control plane.
//
// UI-only, like the rest of /automation/*, and that matters more here than it looks. No
// capability manages triggers and capreg.Deps holds no trigger store: a token that could
// author one could arm a run against traffic it is not otherwise permitted to reach, and
// Deps is the documented place where that kind of authority leaks in — internal/automation
// is not an import cycle, so the compiler would not catch it.

// requireTriggers reports whether the custom trigger store is available, writing the JSON
// 404 if not.
//
// Absent means the file could not be read at startup, which is deliberately fatal for the
// feature rather than silently empty: an empty store would make every automation
// referencing a custom trigger read as unreferenced and start firing on its raw event.
//
// It does not gate on automation. A trigger is a shared named object with two consumers now,
// and a webhook is available with no automation flag at all — routing this through
// requireAutomations would leave the webhook editor unable to list the triggers it references.
// Nothing about the trust story changes: these routes stay UI-only, and no capability reaches
// them either way.
func (s *APIServer) requireTriggers(w http.ResponseWriter) *trigger.Store {
	if s.triggers == nil {
		writeError(w, http.StatusNotFound,
			"custom triggers are unavailable on this instance; see the startup log for why "+
				"~/.joro/triggers.json could not be read")
		return nil
	}
	return s.triggers
}

// triggerRow is one row of the list: the trigger, plus what it would break.
type triggerRow struct {
	trigger.Trigger
	// UsedBy names the automations referencing this trigger. Sent for every row because
	// the list is where an operator decides whether to edit one, and editing a shared
	// trigger changes every automation in this field.
	UsedBy []string `json:"usedBy"`
}

func (s *APIServer) handleListTriggers(w http.ResponseWriter, r *http.Request) {
	store := s.requireTriggers(w)
	if store == nil {
		return
	}
	all := store.All()
	rows := make([]triggerRow, 0, len(all))
	for _, t := range all {
		rows = append(rows, triggerRow{Trigger: t, UsedBy: s.triggerUsedBy(t.ID)})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"triggers": rows,

		// The condition vocabulary: which fields each event carries and the operators each
		// takes. Served rather than restated in the frontend, for the reason the command
		// vocabulary is — a field added in Go appears in the canvas's selects with no
		// client change, and the client can never offer a pairing the server would refuse.
		// An event absent from the map carries nothing to test.
		"fields":    trigger.Fields(),
		"limits":    trigger.GraphLimits(),
		"ops":       trigger.Ops(),
		"nodeTypes": trigger.NodeTypes,
		"events":    trigger.Events,
	})
}

// triggerUsedBy names everything referencing a trigger: automations and webhooks both.
//
// The union, not just the automations. A trigger is shared, and deleting one out from under a
// webhook fails safe — a dangling reference never fires — but silently, which is the failure
// internal/trigger is arranged to make loud. Missing a consumer here is what would make it
// quiet again.
//
// Read from both sets on every call rather than kept as an index: they are small, this is an
// operator-paced endpoint, and an index would be a second copy of the truth that could
// disagree about what is actually referenced.
func (s *APIServer) triggerUsedBy(id string) []string {
	out := []string{}
	if s.scriptManager != nil && s.scriptManager.Packages() != nil {
		for _, a := range s.scriptManager.Packages().List() {
			for _, ref := range a.Manifest.Triggers {
				if string(ref) == id {
					out = append(out, a.Manifest.Name)
					break
				}
			}
		}
	}
	out = append(out, s.webhooks.UsedBy(id)...)
	sort.Strings(out)
	return out
}

func (s *APIServer) handleGetTrigger(w http.ResponseWriter, r *http.Request) {
	store := s.requireTriggers(w)
	if store == nil {
		return
	}
	id := r.PathValue("id")

	// A built-in resolves too, so the editor can open one read-only and clone it without
	// having to know which kind it is looking at before it asks.
	t, err := store.Resolve(id)
	if err != nil {
		writeTriggerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, triggerRow{Trigger: t, UsedBy: s.triggerUsedBy(id)})
}

func (s *APIServer) handleCreateTrigger(w http.ResponseWriter, r *http.Request) {
	store := s.requireTriggers(w)
	if store == nil {
		return
	}
	var body trigger.Trigger
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := store.Create(body)
	if err != nil {
		writeTriggerError(w, err)
		return
	}
	// The dispatcher caches compiled triggers and reloads on the store's revision, which
	// has just moved; waking it means an operator who saves and then browses does not wait
	// out a tick to see it fire.
	s.scriptTriggers.Wake()
	writeJSON(w, http.StatusOK, triggerRow{Trigger: created, UsedBy: []string{}})
}

func (s *APIServer) handleUpdateTrigger(w http.ResponseWriter, r *http.Request) {
	store := s.requireTriggers(w)
	if store == nil {
		return
	}
	id := r.PathValue("id")
	if trigger.IsBuiltin(id) {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("%q is a built-in trigger and cannot be edited; clone it to a custom one", id))
		return
	}
	var body trigger.Trigger
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := store.Update(id, body)
	if err != nil {
		writeTriggerError(w, err)
		return
	}
	s.scriptTriggers.Wake()
	writeJSON(w, http.StatusOK, triggerRow{Trigger: updated, UsedBy: s.triggerUsedBy(id)})
}

func (s *APIServer) handleDeleteTrigger(w http.ResponseWriter, r *http.Request) {
	store := s.requireTriggers(w)
	if store == nil {
		return
	}
	id := r.PathValue("id")
	if trigger.IsBuiltin(id) {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("%q is a built-in trigger and cannot be deleted", id))
		return
	}
	// Refused while anything references it, rather than deleted and left to fail closed at
	// dispatch. Both are safe — a dangling reference never fires — but only one of them
	// tells the operator now, while they are looking at the thing they were about to break.
	if err := store.Delete(id, s.triggerUsedBy(id)); err != nil {
		writeTriggerError(w, err)
		return
	}
	s.scriptTriggers.Wake()
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleTestTrigger dry-runs a trigger against recent traffic.
//
// It takes a whole trigger rather than an id on purpose: the operator is testing something
// they have not saved yet, and requiring a save first would make the try-it step cost a
// stored — and therefore referenceable — trigger. Nothing is stored and nothing is run.
//
// The response is a 200 carrying valid:false for a graph that will not compile. The request
// was well-formed and the answer is about the graph, which is what the canvas renders
// either way — a 400 would make the editor treat an ordinary bad regex as a failed call.
func (s *APIServer) handleTestTrigger(w http.ResponseWriter, r *http.Request) {
	if s.requireTriggers(w) == nil {
		return
	}
	var body struct {
		trigger.Trigger
		Limit int `json:"limit"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// A draft has no id yet and does not need one to be tested, so stand one in rather
	// than reject it: Validate checks identity as well as shape, and the operator is
	// asking about the shape.
	if body.ID == "" {
		body.ID = "draft"
	}
	writeJSON(w, http.StatusOK, trigger.Test(s.store, body.Trigger, body.Limit))
}

// handleSeedTrigger returns the graph a new trigger starts from.
//
// Served rather than built in the client so the starting point cannot drift from what the
// server will accept — a seed that failed Validate would open the canvas on an error.
func (s *APIServer) handleSeedTrigger(w http.ResponseWriter, r *http.Request) {
	if s.requireTriggers(w) == nil {
		return
	}
	on := r.URL.Query().Get("on")
	if !trigger.Dispatched(on) {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("%q is not an event a trigger can watch", on))
		return
	}
	writeJSON(w, http.StatusOK, trigger.Trigger{On: on, Graph: trigger.SeedGraph(on)})
}

func writeTriggerError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, trigger.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such trigger")
	case errors.Is(err, trigger.ErrExists), errors.Is(err, trigger.ErrInUse):
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}

// triggerRefsFor lists the custom triggers an automation references, for the export
// bundle. A package that names one is not closed over any more, so what it names has to
// travel with it.
func (s *APIServer) triggerRefsFor(m jsautomation.Manifest) []trigger.Trigger {
	out := []trigger.Trigger{}
	if s.triggers == nil {
		return out
	}
	for _, ref := range m.Triggers {
		if trigger.IsBuiltin(string(ref)) {
			continue
		}
		if t, err := s.triggers.Get(string(ref)); err == nil {
			out = append(out, t)
		}
	}
	return out
}
