package chainrun

import (
	"fmt"

	"github.com/BishopFox/joro/internal/chain"
)

// classify decides one cell's state by comparing it to the baseline row.
//
// Only a send that produced a response reaches here with an empty Cell; error,
// unresolved and skipped are decided before or instead of sending, and keep the
// state they arrived with.
func classify(run *Run, variantIdx, stepIdx int, res *Result) {
	if res.Cell != "" {
		return
	}
	if variantIdx == 0 {
		// The baseline is the comparison basis, so it matches itself. A failing
		// baseline is still worth saying out loud, and the baseline verdict's
		// detail is where that is reported — a per-cell state cannot, because
		// there is nothing to compare it against.
		res.Cell = CellOK
		return
	}

	base, ok := run.baselineOf(stepIdx)
	if !ok || base.StructHash == "" {
		// The baseline never got a response for this step, so there is nothing
		// to compare against and saying "ok" would be a guess in the direction
		// that hides a finding.
		res.Cell = CellChanged
		res.Note = appendNote(res.Note, "no baseline for this step")
		return
	}

	if res.StructHash == base.StructHash {
		res.Cell = CellOK
		return
	}
	if base.Status > 0 && base.Status < 400 && res.Status >= 400 {
		res.Cell = CellBlocked
		return
	}
	res.Cell = CellChanged
}

// verdictFor decides what one variant proved.
//
// The rubric is computed here and ships on the result, so the frontend renders it
// and never recomputes it — one fewer mirror to keep in sync, the rule
// apiscan.Triage and sjStatus.tsx already follow.
func verdictFor(run *Run, variantIdx int, variant chain.Variant, stepIndex map[string]int) Verdict {
	v := Verdict{VariantID: variant.ID, Kind: variant.Kind, Label: variant.Label}
	ch := run.Config.Chain
	base := variantIdx * run.Stride

	goal, hasGoal := ch.GoalStep()
	if !hasGoal {
		v.Verdict = VerdictInconclusive
		v.Detail = "the chain has no steps"
		return v
	}

	// Walk the variant in execution order up to the goal. A replay that fell
	// apart before reaching the goal says nothing about the application, and
	// this check runs first because inconclusive dominates every other verdict:
	// reporting a broken replay as "enforced" fails in the direction that hides
	// a real finding, which is the polarity apiscan.verdictFor and
	// trigger.Compile both settle on.
	// The goal is checked too, then the walk stops. Breaking before it left the
	// deciding step as the only one whose failure went unnoticed: "unresolved"
	// is a non-empty cell, so it reached the switch below as a not-OK answer and
	// read as enforced.
	for _, stepID := range variant.Steps {
		idx, ok := stepIndex[stepID]
		if !ok {
			if stepID == goal.ID {
				break
			}
			continue
		}
		cell, ok := run.slotAt(base + idx)
		if ok {
			switch cell.Cell {
			case CellUnresolved:
				v.Verdict = VerdictInconclusive
				v.Detail = fmt.Sprintf("%s could not run: %s", cell.Label, cell.Note)
				return v
			case CellError:
				v.Verdict = VerdictInconclusive
				v.Detail = fmt.Sprintf("%s failed to send: %s", cell.Label, cell.Error)
				return v
			}
		}
		if stepID == goal.ID {
			break
		}
	}

	goalIdx, ok := stepIndex[goal.ID]
	if !ok {
		v.Verdict = VerdictInconclusive
		v.Detail = "the goal step is not in the chain"
		return v
	}
	goalCell, ok := run.slotAt(base + goalIdx)
	if !ok || goalCell.Cell == "" {
		v.Verdict = VerdictInconclusive
		v.Detail = "the goal step did not run"
		return v
	}

	switch variant.Kind {
	case chain.VariantBaseline:
		v.Verdict = VerdictBaseline
		if bad := failingBaselineSteps(run, ch); bad != "" {
			// Not a verdict of its own: the baseline is still the comparison
			// basis. But a baseline whose own steps are failing makes every
			// other verdict in the run suspect, and the operator has to know.
			v.Detail = "baseline steps did not succeed: " + bad
		}
		return v

	case chain.VariantRepeat:
		// Repeat asks a stricter question than skip does, so it reads the
		// stricter hash. "Did the goal still work" is not interesting here —
		// it did — "did anything about its answer change" is, and a total
		// falling from 90 to 80 is exactly the change StructHash folds away.
		//
		// When the repeated step is the goal, the answer in question is the
		// second one. Occurrence 0 owns the grid slot and ran before the repeat,
		// so comparing it reports every double-submit as idempotent.
		cmp := goalCell
		if variant.Target == goal.ID {
			if last, ok := run.lastOccurrence(variant.ID, goal.ID); ok {
				cmp = last
			}
			switch cmp.Cell {
			case CellUnresolved, CellError:
				v.Verdict = VerdictInconclusive
				v.Detail = fmt.Sprintf("the second %s did not run", goal.Label)
				return v
			}
		}
		baseGoal, haveBase := run.baselineOf(goalIdx)
		if haveBase && cmp.CanonHash != "" && cmp.CanonHash == baseGoal.CanonHash {
			v.Verdict = VerdictIdempotent
			v.Detail = fmt.Sprintf("repeating %s did not change %s", labelOf(ch, variant.Target), goal.Label)
			return v
		}
		v.Verdict = VerdictAmplified
		v.Detail = fmt.Sprintf("repeating %s changed what %s returned",
			labelOf(ch, variant.Target), goal.Label)
		return v

	default: // omit, move
		if goalCell.Cell == CellOK {
			v.Verdict = VerdictBypassed
			v.Detail = fmt.Sprintf("%s answered exactly as it did in the baseline", goal.Label)
			return v
		}
		v.Verdict = VerdictEnforced
		v.Detail = fmt.Sprintf("%s answered %d (%s)", goal.Label, goalCell.Status, goalCell.Cell)
		return v
	}
}

// failingBaselineSteps names the baseline steps that did not succeed.
func failingBaselineSteps(run *Run, ch *chain.Chain) string {
	var bad []string
	for idx, s := range ch.Steps {
		cell, ok := run.slotAt(idx)
		if !ok {
			continue
		}
		if cell.Cell == CellError || cell.Cell == CellUnresolved || (cell.Status >= 400 && cell.Status != 0) {
			bad = append(bad, fmt.Sprintf("%s (%d)", s.Label, cell.Status))
		}
	}
	if len(bad) == 0 {
		return ""
	}
	if len(bad) > 3 {
		return fmt.Sprintf("%s and %d more", bad[0], len(bad)-1)
	}
	return joinComma(bad)
}

func labelOf(ch *chain.Chain, stepID string) string {
	if s, _, ok := ch.StepByID(stepID); ok {
		return s.Label
	}
	return stepID
}

func joinComma(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

func appendNote(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}

// GridView is the whole result matrix, materialized for one render.
type GridView struct {
	RunID    string          `json:"runId"`
	Steps    []StepHead      `json:"steps"`
	Variants []chain.Variant `json:"variants"`
	Rows     []Row           `json:"rows"`
	Summary  map[string]int  `json:"summary"`

	// Interesting lists the variant ids worth looking at first.
	Interesting []string `json:"interesting"`
}

// Row is one variant across every step.
type Row struct {
	Variant chain.Variant `json:"variant"`
	Cells   []Result      `json:"cells"`
	Verdict Verdict       `json:"verdict"`
}

// Grid pivots a run into the matrix the tab renders.
func Grid(run *Run) GridView {
	run.mu.RLock()
	results := append([]Result(nil), run.results...)
	verdicts := make(map[string]Verdict, len(run.verdicts))
	for k, v := range run.verdicts {
		verdicts[k] = v
	}
	run.mu.RUnlock()

	out := GridView{
		RunID:    run.ID,
		Steps:    run.Steps,
		Variants: run.Variants,
		// Materialized non-nil, for the reason chain.Chain.Normalize records:
		// a nil slice ships JSON null against a TypeScript array type.
		Rows:        []Row{},
		Summary:     map[string]int{},
		Interesting: []string{},
	}

	for vi, variant := range run.Variants {
		row := Row{Variant: variant, Cells: []Result{}, Verdict: verdicts[variant.ID]}
		for si := range run.Steps {
			idx := vi*run.Stride + si
			if idx < len(results) {
				res := results[idx]
				res.ReqRaw, res.RespRaw = nil, nil
				row.Cells = append(row.Cells, res)
			} else {
				row.Cells = append(row.Cells, Result{})
			}
		}
		out.Rows = append(out.Rows, row)
		if row.Verdict.Verdict != "" {
			out.Summary[row.Verdict.Verdict]++
		}
		if row.Verdict.Verdict == VerdictBypassed || row.Verdict.Verdict == VerdictAmplified {
			out.Interesting = append(out.Interesting, variant.ID)
		}
	}
	return out
}
