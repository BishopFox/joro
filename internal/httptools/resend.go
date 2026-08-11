package httptools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/proxy"
)

// Resend timeouts.
const (
	DefaultResendTimeoutMs = 15000
	MaxResendTimeoutMs     = 60000
)

// ResendArgs is the argument shape of http.resend.
//
// There is no followRedirects field, deliberately. A 302 to another host is a
// one-line scope bypass: the guard checked the host in these arguments, and a
// redirect would take the connection somewhere it never approved. A client follows
// a redirect by reading the Location from the result and issuing a second,
// separately guarded call.
type ResendArgs struct {
	Ref                 int    `json:"ref"`
	Edits               []Edit `json:"edits"`
	Scheme              string `json:"scheme"`
	Host                string `json:"host"`
	UpdateContentLength *bool  `json:"updateContentLength"`
	TimeoutMs           int    `json:"timeoutMs"`
	UseContext          *bool  `json:"useContext"`
}

// ResendDeps is what a resend needs from the host process.
type ResendDeps struct {
	Send  SendDeps
	Store *proxy.Store

	// Contexts is the per-principal cookie jar; TokenID selects this caller's.
	// Both may be zero, in which case sends are stateless.
	Contexts *Contexts
	TokenID  string
}

// TargetOf resolves the scheme and host a resend will dial, without sending.
//
// This is what the capability's TargetExtractor calls, so the scope guard checks
// the same destination the send will actually use. It reads the capture store,
// which is why explicit host arguments and the captured URL have to agree on
// precedence here and in Resend.
func TargetOf(store *proxy.Store, ref int, scheme, host string, edits []Edit) (dialScheme, dialHost, method, path string, err error) {
	item := store.GetBySeq(ref)
	if item == nil {
		return "", "", "", "", fmt.Errorf("no captured request with seq %d", ref)
	}
	capScheme, capHost := hostFromCapture(item.URL)
	dialScheme = firstNonEmpty(strings.ToLower(scheme), capScheme, "https")
	dialHost = firstNonEmpty(host, capHost)
	if dialHost == "" {
		dialHost = item.Host
	}

	// Apply the edits so the guard sees the method and path that will be sent,
	// not the ones that were captured. An agent editing the path to a different
	// scope-excluded prefix must be caught here, not after the bytes are on the
	// wire.
	raw := item.ReqRaw
	if len(edits) > 0 {
		if edited, eerr := ApplyEdits(raw, edits); eerr == nil {
			raw = edited
		}
	}
	m, target, _, ok := requestLine(firstLine(raw))
	if !ok {
		return dialScheme, dialHost, item.Method, "/", nil
	}
	p, _ := splitTarget(target)
	if !strings.HasPrefix(p, "/") {
		// Absolute-form target; take its path component.
		if _, hostOnly := hostFromCapture(p); hostOnly != "" {
			p = "/"
		}
	}
	return dialScheme, dialHost, m, p, nil
}

// Resend applies structural edits to a captured request and sends it through
// Joro's proxy, returning a fingerprint rather than a body.
func Resend(ctx context.Context, d ResendDeps, args ResendArgs) (string, error) {
	item := d.Store.GetBySeq(args.Ref)
	if item == nil {
		return "", fmt.Errorf("no captured request with seq %d", args.Ref)
	}
	if len(item.ReqRaw) == 0 {
		return "", fmt.Errorf("request %d has no captured bytes to resend", args.Ref)
	}

	raw, err := ApplyEdits(item.ReqRaw, args.Edits)
	if err != nil {
		return "", err
	}
	if args.UpdateContentLength == nil || *args.UpdateContentLength {
		raw = proxy.UpdateContentLength(raw)
	}

	scheme, host, _, _, err := TargetOf(d.Store, args.Ref, args.Scheme, args.Host, args.Edits)
	if err != nil {
		return "", err
	}

	timeout := time.Duration(clampInt(args.TimeoutMs, DefaultResendTimeoutMs, 1000, MaxResendTimeoutMs)) * time.Millisecond
	sendCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	u := requestURL(scheme, host, raw)
	var supplied []string
	if args.UseContext == nil || *args.UseContext {
		raw, supplied = d.Contexts.Apply(d.TokenID, u, raw, editsTouchCookies(args.Edits))
		if len(supplied) > 0 {
			raw = proxy.UpdateContentLength(raw)
		}
	}

	res, err := SendViaProxy(sendCtx, raw, scheme, host, d.Send)
	if err != nil {
		return "", annotateSendErr(err, timeout)
	}
	if args.UseContext == nil || *args.UseContext {
		d.Contexts.Capture(d.TokenID, u, res.RespRaw)
	}

	fp := fingerprintResponse(res.Seq, res.RespRaw, res.Duration.Milliseconds(), false)
	return renderResend(args, res, fp, supplied), nil
}

// annotateSendErr explains the failure mode a client is most likely to hit and
// least likely to diagnose: its request is sitting in the operator's intercept
// queue, which looks identical to a hung target from here.
func annotateSendErr(err error, timeout time.Duration) error {
	msg := err.Error()
	if strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "use of closed network connection") {
		return fmt.Errorf("%w — no response within %s. If request interception is enabled in Joro, "+
			"this request is paused in the Intercept queue: forward or drop it, or turn interception off", err, timeout)
	}
	return err
}

func renderResend(args ResendArgs, res *ProxySendResult, fp Fingerprint, supplied []string) string {
	var b strings.Builder

	seqLabel := "seq " + itoa(res.Seq)
	if res.Seq == 0 {
		seqLabel = "seq -"
	}
	fmt.Fprintf(&b, "%s <- ref %d (%d edits)  %s %s\n", seqLabel, args.Ref, len(args.Edits), res.Method, res.URL)
	fmt.Fprintf(&b, "status=%d len=%d ms=%d ct=%s bhash=%s shash=%s words=%d lines=%d\n",
		fp.Status, fp.Len, fp.DurationMs, fp.CT, fp.BodyHash, fp.StructHash, fp.Words, fp.Lines)
	if fp.Note != "" || fp.Server != "" || fp.Decoded != "" {
		var bits []string
		if fp.Note != "" {
			bits = append(bits, "note="+fp.Note)
		}
		if fp.Server != "" {
			bits = append(bits, "server="+fp.Server)
		}
		if fp.Decoded != "" {
			bits = append(bits, "decoded="+fp.Decoded)
		}
		b.WriteString(strings.Join(bits, " ") + "\n")
	}
	if note := contextNote(supplied); note != "" {
		b.WriteString(note + "\n")
	}

	if res.Seq == 0 {
		fmt.Fprintf(&b, "note: %s, so this response is not addressable by seq\n", res.SeqNote)
		return strings.TrimRight(b.String(), "\n")
	}
	// A breadcrumb: the exact follow-up calls with the handle already filled in.
	// Models follow these; without them they guess at argument shapes and spend a
	// call finding out.
	fmt.Fprintf(&b, "read: http_read{ref:%d}   diff: http_diff{a:%d,b:%d}", res.Seq, args.Ref, res.Seq)
	return b.String()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
