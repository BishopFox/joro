package capreg

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/BishopFox/joro/internal/capability"
)

type contextClearArgs struct {
	Host string `json:"host"`
}

func registerExecContext(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:    "context.get",
		Class: capability.ClassContext,
		Title: "Read this token's session cookies",
		Description: "The cookies http_resend and http_batch are holding for you, by host. Set-Cookie from " +
			"every send is recorded here and replayed on later sends to the same host, so a login through " +
			"http_resend keeps subsequent requests authenticated without you handling the cookie. Values are " +
			"shown only if this token has credential visibility; names and hosts always are.",
		InputSchema:    json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		ArgsExample:    json.RawMessage(`{}`),
		MaxOutputBytes: 16 << 10,
		Handler: capability.Typed(func(ctx context.Context, p capability.Principal, _ struct{}) (any, error) {
			if d.Contexts == nil {
				return nil, fmt.Errorf("the execution context is unavailable")
			}
			cookies := d.Contexts.List(p.TokenID, p.AllowCredentials)
			if len(cookies) == 0 {
				return "(no session cookies held; send an authenticated request with http_resend to populate this)", nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "n=%d\n", len(cookies))
			for _, c := range cookies {
				if p.AllowCredentials {
					fmt.Fprintf(&b, "%s  %s=%s\n", c.Host, c.Name, c.Value)
				} else {
					fmt.Fprintf(&b, "%s  %s=<withheld>\n", c.Host, c.Name)
				}
			}
			return strings.TrimRight(b.String(), "\n"), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:       "context.clear",
		Class:    capability.ClassContext,
		Title:    "Drop this token's session cookies",
		Mutating: true,
		Description: "Forget the cookies held for you, for one host or for all of them. Use this to test as an " +
			"unauthenticated user after logging in, or before authenticating as a different account. Affects " +
			"only this token's own session; the operator's browser is untouched.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "host": {"type":"string","description":"Clear only this host. Omit to clear everything."}
  },
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{}`),
		MaxOutputBytes: 4 << 10,
		Handler: capability.Typed(func(ctx context.Context, p capability.Principal, args contextClearArgs) (any, error) {
			if d.Contexts == nil {
				return nil, fmt.Errorf("the execution context is unavailable")
			}
			n := d.Contexts.Clear(p.TokenID, args.Host)
			scope := orDefault(strings.TrimSpace(args.Host), "all hosts")
			capability.RecordChange(ctx, "clear session cookies for %s (%d)", scope, n)
			return fmt.Sprintf("cleared %d cookie(s) for %s", n, scope), nil
		}),
	})
}
