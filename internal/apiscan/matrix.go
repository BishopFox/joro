package apiscan

import (
	"sort"
	"strings"
)

// Verdict is what one operation's row across every profile amounts to.
type Verdict string

const (
	// VerdictOpen means the least-privileged profile — normally anonymous —
	// was served. This is the single most valuable thing the matrix finds, and
	// it needs no comparison at all.
	VerdictOpen Verdict = "open"

	// VerdictBroken means a lower-privileged profile got the same response a
	// higher-privileged one did, while some profile below it was refused. That
	// is broken access control: the endpoint distinguishes *some* callers, so it
	// is not simply public, but it fails to distinguish the one that matters.
	VerdictBroken Verdict = "broken"

	// VerdictDenied means every profile was refused.
	VerdictDenied Verdict = "denied"

	// VerdictExpected means authorization rises with privilege, as intended.
	VerdictExpected Verdict = "expected"

	// VerdictError means a cell could not be evaluated.
	VerdictError Verdict = "error"
)

// Cell is one operation under one profile.
type Cell struct {
	ProfileID  string `json:"profileId"`
	Rank       int    `json:"rank"`
	Status     int    `json:"status"`
	Len        int    `json:"len"`
	BodyHash   string `json:"bhash,omitempty"`
	StructHash string `json:"shash,omitempty"`
	DurationMs int64  `json:"ms"`
	Seq        int    `json:"seq"`
	RequestID  string `json:"requestId,omitempty"`
	Triage     Triage `json:"triage"`
	Index      int    `json:"index"`
	Error      string `json:"error,omitempty"`
	Skipped    string `json:"skipped,omitempty"`
}

// Row is one operation across every profile, in ascending privilege order.
type Row struct {
	OpID    string  `json:"opId"`
	Method  string  `json:"method"`
	Path    string  `json:"path"`
	Cells   []Cell  `json:"cells"`
	Verdict Verdict `json:"verdict"`
	Detail  string  `json:"detail,omitempty"`
}

// MatrixView is the pivoted result.
type MatrixView struct {
	RunID       string         `json:"runId"`
	Profiles    []Profile      `json:"profiles"`
	Rows        []Row          `json:"rows"`
	Summary     map[string]int `json:"summary"`
	Interesting []string       `json:"interesting"`
}

// Matrix pivots a run's results into the operations-by-profiles grid and
// computes each row's verdict.
//
// The verdict is computed here rather than in the client for the reason
// httptools.renderBatch states about its outliers line: the answer is
// precomputed and the table is corroboration. Deciding it in TypeScript would
// put privilege comparison in two places and create a keep-in-sync pair nobody
// maintains.
func Matrix(run *Run) MatrixView {
	cfg := run.Config
	results := run.Results()

	// Profiles are compared in privilege order, which is what makes "a lower
	// rank reached what only a higher rank should" a statement about privilege
	// rather than about two arbitrary credential sets.
	order := make([]int, len(cfg.Profiles))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		return cfg.Profiles[order[a]].Rank < cfg.Profiles[order[b]].Rank
	})
	ordered := make([]Profile, len(order))
	for i, idx := range order {
		ordered[i] = cfg.Profiles[idx]
	}

	// Materialized rather than left nil: a nil slice marshals as null, and the
	// client's type says array. See apispec.Spec.normalize for the rule.
	view := MatrixView{
		RunID: run.ID, Profiles: ordered,
		Rows: []Row{}, Interesting: []string{}, Summary: map[string]int{},
	}
	if len(cfg.Profiles) == 0 {
		return view
	}

	for opIdx := range cfg.Ops {
		op := cfg.Ops[opIdx]
		row := Row{OpID: op.ID, Method: op.Method, Path: op.Path, Cells: []Cell{}}
		for _, profIdx := range order {
			idx := opIdx*len(cfg.Profiles) + profIdx
			if idx >= len(results) {
				continue
			}
			r := results[idx]
			row.Cells = append(row.Cells, Cell{
				ProfileID: cfg.Profiles[profIdx].ID, Rank: cfg.Profiles[profIdx].Rank,
				Status: r.Status, Len: r.Len, BodyHash: r.BodyHash, StructHash: r.StructHash,
				DurationMs: r.DurationMs, Seq: r.Seq, RequestID: r.RequestID,
				Triage: r.Triage, Index: r.Index, Error: r.Error, Skipped: r.Skipped,
			})
		}
		row.Verdict, row.Detail = verdictFor(row.Cells)
		view.Summary[string(row.Verdict)]++
		if row.Verdict == VerdictOpen || row.Verdict == VerdictBroken {
			view.Interesting = append(view.Interesting, op.ID)
		}
		view.Rows = append(view.Rows, row)
	}
	return view
}

// verdictFor classifies one row. Cells arrive in ascending privilege order.
func verdictFor(cells []Cell) (Verdict, string) {
	var usable []Cell
	firstErr := ""
	for _, c := range cells {
		if c.Error != "" {
			// Held, not returned: a failure in a privileged column must not bury
			// "anonymous was served", which needs no comparison. Still an error
			// for every rule that does need the whole row.
			if firstErr == "" {
				firstErr = c.Error
			}
			continue
		}
		if c.Skipped != "" {
			continue
		}
		// A slot that has not been filled yet is the zero Result: no error, no
		// skip reason, and an empty Triage. Treating it as usable would walk it
		// past every rule below and land on VerdictExpected — reporting an
		// operation that was never sent as correctly authorized. For a grid whose
		// whole purpose is finding access-control failures, failing open is the
		// wrong direction, and GET /runs/{id}/matrix can be called mid-run.
		if c.Triage == "" {
			return VerdictError, "this operation has not been sent yet"
		}
		usable = append(usable, c)
	}
	if len(usable) == 0 {
		if firstErr != "" {
			return VerdictError, "a request could not be completed: " + firstErr
		}
		return VerdictError, "no request was sent for this operation"
	}

	// The least-privileged profile being served needs no comparison. cells[0],
	// not usable[0]: if the anonymous column is the one that errored, usable[0]
	// holds credentials and calling its 200 "open" invents a finding.
	if len(cells) > 0 && cells[0].Error == "" && cells[0].Skipped == "" && cells[0].Triage == TriageGood {
		return VerdictOpen, "the least-privileged profile was served"
	}
	if firstErr != "" {
		return VerdictError, "a request could not be completed: " + firstErr
	}

	allDenied := true
	for _, c := range usable {
		if c.Triage != TriageBad {
			allDenied = false
			break
		}
	}
	if allDenied {
		return VerdictDenied, "every profile was refused"
	}

	// Broken access control: the most-privileged profile was served, a
	// less-privileged one got a structurally identical response, and something
	// below that was refused.
	//
	// StructHash rather than status and length is what makes this work. Two
	// renderings of one page carrying different CSRF tokens have different
	// lengths and different body hashes but the same struct hash, so a
	// length comparison misses the finding and a body comparison flags every
	// row.
	top := usable[len(usable)-1]
	if top.Triage == TriageGood && top.StructHash != "" {
		for i := 0; i < len(usable)-1; i++ {
			lower := usable[i]
			if lower.Triage != TriageGood || lower.StructHash != top.StructHash {
				continue
			}
			for j := 0; j < i; j++ {
				if usable[j].Triage == TriageBad {
					return VerdictBroken, strings.Join([]string{
						"profile", lower.ProfileID, "received the same response as", top.ProfileID,
						"while", usable[j].ProfileID, "was refused",
					}, " ")
				}
			}
		}
	}

	return VerdictExpected, ""
}
