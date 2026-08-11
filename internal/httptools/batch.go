package httptools

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/proxy"
)

// Batch caps.
//
// Fifty and ten are chosen against the fuzzer, not arbitrarily. The fuzzer exists,
// has a UI, streams results, and handles a hundred threads and ten-million-item
// cartesian products. This is for the five-to-forty request comparisons an agent
// actually reasons about: header permutations, a run of object ids, a set of auth
// states. Past roughly fifty rows the output stops fitting a model's useful
// attention anyway, and the right answer becomes "drive the fuzzer" — which is
// what the refusal says.
const (
	MaxBatchVariants      = 50
	DefaultBatchConc      = 4
	MaxBatchConc          = 10
	MaxBatchRatePerSec    = 50
	DefaultBatchTimeoutMs = 10000
	DefaultBatchBudgetMs  = 60000
	MaxBatchBudgetMs      = 120000
	maxBatchLabelLen      = 24
)

// BatchVariant is one labelled set of edits.
type BatchVariant struct {
	Label string `json:"label"`
	Edits []Edit `json:"edits"`
}

// BatchArgs is the argument shape of http.batch.
type BatchArgs struct {
	Ref           int            `json:"ref"`
	Variants      []BatchVariant `json:"variants"`
	Scheme        string         `json:"scheme"`
	Host          string         `json:"host"`
	Concurrency   int            `json:"concurrency"`
	RatePerSec    float64        `json:"ratePerSec"`
	TimeoutMs     int            `json:"timeoutMs"`
	TotalBudgetMs int            `json:"totalBudgetMs"`
	UseContext    *bool          `json:"useContext"`
}

type batchRow struct {
	label string
	fp    Fingerprint
	seq   int
	err   string
	ctx   []string // cookie names the execution context supplied
}

// Batch sends a set of edited variants of one captured request and renders a
// comparison table.
//
// The execution shape mirrors fuzzer.Run — a shared ticker as the rate limiter, a
// channel of indices, N workers — without importing it. Nothing in internal/fuzzer
// is exported for reuse: executePayload is unexported and coupled to a Campaign,
// its broadcast channel and its matcher machinery, and extracting it would be a
// behavior change to the fuzzer. Duplicating the shape is the repo's existing
// answer to this (h2_mitm.go mirrors replace.go the same way).
func Batch(ctx context.Context, d ResendDeps, args BatchArgs) (string, error) {
	item := d.Store.GetBySeq(args.Ref)
	if item == nil {
		return "", fmt.Errorf("no captured request with seq %d", args.Ref)
	}
	if len(args.Variants) == 0 {
		return "", fmt.Errorf("variants is required")
	}
	if len(args.Variants) > MaxBatchVariants {
		return "", fmt.Errorf(
			"%d variants exceeds the %d-variant limit for http_batch. This tool is for comparisons an "+
				"agent reads; for a larger run, drive Joro's fuzzer from the Fuzz tab",
			len(args.Variants), MaxBatchVariants)
	}
	for i, v := range args.Variants {
		if strings.TrimSpace(v.Label) == "" {
			return "", fmt.Errorf("variant %d has no label; labels are what correlate rows back to your edits", i)
		}
	}

	conc := clampInt(args.Concurrency, DefaultBatchConc, 1, MaxBatchConc)
	perItem := time.Duration(clampInt(args.TimeoutMs, DefaultBatchTimeoutMs, 1000, MaxResendTimeoutMs)) * time.Millisecond
	budget := time.Duration(clampInt(args.TotalBudgetMs, DefaultBatchBudgetMs, 1000, MaxBatchBudgetMs)) * time.Millisecond

	runCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	var limiter <-chan time.Time
	if args.RatePerSec > 0 {
		rate := min(args.RatePerSec, MaxBatchRatePerSec)
		tick := time.NewTicker(time.Duration(float64(time.Second) / rate))
		defer tick.Stop()
		limiter = tick.C
	}

	scheme, host, _, _, err := TargetOf(d.Store, args.Ref, args.Scheme, args.Host, nil)
	if err != nil {
		return "", err
	}

	// One claim set per batch, so two workers finishing at once cannot correlate
	// their sends to the same history row.
	sendDeps := d.Send
	sendDeps.Claims = newClaimSet()

	// Results land in a pre-sized slice indexed by variant, not appended. Order
	// matters more here than in the fuzzer, because the client correlates rows
	// back to the variants it wrote.
	// The jar is read once up front and never written from a worker: variants run
	// concurrently, so letting each one capture Set-Cookie would make which cookie
	// wins depend on scheduling. A batch is a comparison, and every row must start
	// from the same session state.
	useContext := args.UseContext == nil || *args.UseContext

	rows := make([]batchRow, len(args.Variants))
	work := make(chan int, conc)
	var wg sync.WaitGroup

	start := time.Now()
	for range conc {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range work {
				v := args.Variants[idx]
				rows[idx] = batchRow{label: truncRunes(v.Label, maxBatchLabelLen)}

				if limiter != nil {
					select {
					case <-runCtx.Done():
						rows[idx].err = "budget"
						continue
					case <-limiter:
					}
				}
				if runCtx.Err() != nil {
					rows[idx].err = "budget"
					continue
				}

				raw, err := ApplyEdits(item.ReqRaw, v.Edits)
				if err != nil {
					rows[idx].err = err.Error()
					continue
				}
				raw = proxy.UpdateContentLength(raw)

				if useContext {
					var supplied []string
					raw, supplied = d.Contexts.Apply(d.TokenID,
						requestURL(scheme, host, raw), raw, editsTouchCookies(v.Edits))
					if len(supplied) > 0 {
						raw = proxy.UpdateContentLength(raw)
						rows[idx].ctx = supplied
					}
				}

				itemCtx, itemCancel := context.WithTimeout(runCtx, perItem)
				res, err := SendViaProxy(itemCtx, raw, scheme, host, sendDeps)
				itemCancel()
				if err != nil {
					rows[idx].err = shortErr(err)
					continue
				}
				rows[idx].seq = res.Seq
				rows[idx].fp = fingerprintResponse(res.Seq, res.RespRaw, res.Duration.Milliseconds(), false)
			}
		}()
	}
	for i := range args.Variants {
		work <- i
	}
	close(work)
	wg.Wait()

	return renderBatch(args, rows, time.Since(start)), nil
}

// renderBatch produces the comparison table.
//
// Three devices do the work. The shash column collapses many rows to a handful of
// visually identical strings, which models compare far more reliably than they
// compare numbers. The outliers line is computed here rather than left to the
// client — the answer is precomputed and the table is corroboration. And the base
// preamble states the reference values once instead of making the client infer
// which row is the baseline.
func renderBatch(args BatchArgs, rows []batchRow, elapsed time.Duration) string {
	modal := modalStructHash(rows)

	ok, errs := 0, 0
	for _, r := range rows {
		if r.err == "" {
			ok++
		} else {
			errs++
		}
	}

	t := newTable("seq", "label", "status", "len", "ms", "shash", "words", "lines", "note")
	t.empty = "(no results)"
	t.note(fmt.Sprintf("batch ref=%d n=%d ok=%d err=%d elapsed=%.1fs  base: shash=%s",
		args.Ref, len(rows), ok, errs, elapsed.Seconds(), dash(modal)))

	var outliers []string
	for _, r := range rows {
		if r.err != "" {
			t.add("-", r.label, "-", "-", "-", "-", "-", "-", "err="+truncRunes(r.err, 50))
			continue
		}
		mark := ""
		if modal != "" && r.fp.StructHash != modal {
			mark = "  <<<"
			outliers = append(outliers, seqLabelFor(r))
		}
		t.add(
			seqLabelFor(r), r.label, strconv.Itoa(r.fp.Status), strconv.Itoa(r.fp.Len),
			strconv.FormatInt(r.fp.DurationMs, 10), r.fp.StructHash,
			strconv.Itoa(r.fp.Words), strconv.Itoa(r.fp.Lines),
			dash(r.fp.Note)+mark,
		)
	}

	out := t.String()
	var supplied []string
	for _, r := range rows {
		supplied = mergeNames(supplied, r.ctx)
	}
	if note := contextNote(supplied); note != "" {
		out += "\n" + note
	}
	if len(outliers) > 0 {
		out += fmt.Sprintf("\noutliers: %s (shash differs from the majority)", strings.Join(outliers, " "))
	}
	if errs > 0 {
		out += "\nnote: rows marked err=budget ran out of totalBudgetMs; raise it or lower the variant count"
	}
	return out
}

// modalStructHash returns the most common structural hash, which is the de facto
// baseline whether or not the client labelled one.
func modalStructHash(rows []batchRow) string {
	counts := map[string]int{}
	for _, r := range rows {
		if r.err == "" && r.fp.StructHash != "" {
			counts[r.fp.StructHash]++
		}
	}
	if len(counts) == 0 {
		return ""
	}
	type kv struct {
		k string
		n int
	}
	all := make([]kv, 0, len(counts))
	for k, n := range counts {
		all = append(all, kv{k, n})
	}
	// Sort by count then hash, so a tie is deterministic across runs.
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].k < all[j].k
	})
	return all[0].k
}

func seqLabelFor(r batchRow) string {
	if r.seq == 0 {
		return "-"
	}
	return strconv.Itoa(r.seq)
}

func shortErr(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i > 0 && len(msg)-i < 60 {
		return msg[i+2:]
	}
	return truncRunes(msg, 60)
}
