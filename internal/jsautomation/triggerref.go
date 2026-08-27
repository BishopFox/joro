package jsautomation

import (
	"encoding/json"
	"slices"

	"github.com/BishopFox/joro/internal/trigger"
)

// TriggerRef names what makes an automation run: an event directly, or a custom trigger
// the operator built.
//
// The two share one namespace and cannot collide. Every event name but manual and lens
// contains a dot, and a custom id may not — idPattern excludes it — so only those two
// could clash, and trigger.Validate refuses the whole event list as an id anyway.
type TriggerRef string

// UnmarshalJSON accepts a bare name or an object carrying one.
//
// The object form is what an earlier build of Joro wrote, when a trigger held its
// conditions inline. Reading only the name and discarding the rest is what keeps such a
// manifest loadable: refusing it would make the package vanish from the operator's list
// rather than come back with its conditions gone, and a vanished package is the harder
// failure to diagnose. Its conditions are lost either way — they have somewhere else to
// live now, and no automatic migration could name the trigger they should become.
func (r *TriggerRef) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*r = TriggerRef(s)
		return nil
	}
	var obj struct {
		On string `json:"on"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	*r = TriggerRef(obj.On)
	return nil
}

// MarshalJSON writes a bare name, so a manifest written before any of this existed is
// byte-identical after a load and a save.
func (r TriggerRef) MarshalJSON() ([]byte, error) { return json.Marshal(string(r)) }

// NamedTriggers builds references from bare names, which is what a caller that has only
// names — an agent's install arguments, a hand-built manifest — is stating.
func NamedTriggers(names ...string) []TriggerRef {
	out := make([]TriggerRef, 0, len(names))
	for _, n := range names {
		out = append(out, TriggerRef(n))
	}
	return out
}

// TriggerNames renders references as plain strings, for a caller that only needs to name
// them — an audit line, a tool result, a message listing what an automation subscribes to.
func TriggerNames(refs []TriggerRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, string(r))
	}
	return out
}

// containsRef reports whether refs names this one.
func containsRef(refs []TriggerRef, name string) bool {
	return slices.Contains(refs, TriggerRef(name))
}

// dispatchedRef reports whether the dispatcher watches a reference.
//
// A custom trigger always resolves to a dispatched event — trigger.Validate refuses to
// build one on an event the operator starts by hand — so anything that is not a
// hand-started built-in is watched. A reference to a trigger that does not exist counts as
// watched on purpose: it has to reach the dispatcher to be reported as broken, and
// treating it as unwatched here would hide it instead.
func dispatchedRef(r TriggerRef) bool {
	name := string(r)
	if trigger.IsBuiltin(name) {
		return trigger.Dispatched(name)
	}
	return name != ""
}
