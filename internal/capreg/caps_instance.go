package capreg

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/BishopFox/joro/internal/capability"
)

// instance.get is the orientation call. Without it an agent has to spend four
// separate invocations working out what it is connected to before it can start.
func registerInstance(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:    "instance.get",
		Class: capability.ClassInstance,
		Title: "Describe this Joro instance",
		Description: "What this Joro instance is: version, proxy address, the active project, how much traffic " +
			"has been captured, whether scope, interception and detection are on, and how many findings exist. " +
			"Call this first — it is one request and it tells you whether the state you are about to reason " +
			"about is empty, scoped, or already triaged.",
		InputSchema:    json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		ArgsExample:    json.RawMessage(`{}`),
		MaxOutputBytes: 8 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, _ struct{}) (any, error) {
			var b strings.Builder

			project := "(none)"
			if d.ActiveProject != nil {
				project = orDefault(d.ActiveProject(), "(unsaved session)")
			}
			fmt.Fprintf(&b, "joro %s  proxy=%s  project=%s\n",
				orDefault(d.Version, "unknown"), orDefault(d.ProxyAddr, "unknown"), project)

			if d.Store != nil {
				fmt.Fprintf(&b, "captured=%d\n", d.Store.Count())
			}
			if d.Scope != nil {
				fmt.Fprintf(&b, "scope=%s rules=%d\n", onOff(d.Scope.IsEnabled()), d.Scope.RuleCount())
			}
			if d.Intercept != nil {
				fmt.Fprintf(&b, "intercept requests=%s responses=%s queued=%d\n",
					onOff(d.Intercept.IsEnabled()), onOff(d.Intercept.IsResponseEnabled()),
					len(d.Intercept.List()))
			}
			if d.Engine != nil && d.Findings != nil {
				fmt.Fprintf(&b, "detect=%s findings=%d\n",
					onOff(d.Engine.IsEnabled()), d.Findings.Count())
			}
			return strings.TrimRight(b.String(), "\n"), nil
		}),
	})
}
