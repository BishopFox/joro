package chain

import (
	"fmt"
	"strconv"
)

// GenerateVariants expands a chain into the orderings to execute.
//
// The baseline is always first and always present: it is the comparison basis,
// and it is measured fresh on every run rather than read out of the recording,
// because a recording is hours old and comparing against it would report every
// session-dependent difference as a change the mutation caused.
//
// Setup steps are never mutated. They exist to put the application back into the
// state the variant needs, so omitting, repeating or moving one tests the setup
// rather than the workflow.
//
// The goal step is never omitted. A variant that removes the step whose outcome
// decides the verdict has no verdict to give.
func GenerateVariants(chain *Chain, kinds []string) []Variant {
	order := make([]string, len(chain.Steps))
	for i, s := range chain.Steps {
		order[i] = s.ID
	}

	out := []Variant{{
		ID:    "v1",
		Kind:  VariantBaseline,
		Label: "baseline",
		Steps: order,
	}}
	n := 1
	next := func() string { n++; return "v" + strconv.Itoa(n) }

	goal, hasGoal := chain.GoalStep()
	mutable := func(s Step) bool { return !s.Setup }

	want := make(map[string]bool, len(kinds))
	for _, k := range kinds {
		want[k] = true
	}

	if want[VariantOmit] {
		for i, s := range chain.Steps {
			if !mutable(s) || (hasGoal && s.ID == goal.ID) {
				continue
			}
			steps := make([]string, 0, len(order)-1)
			steps = append(steps, order[:i]...)
			steps = append(steps, order[i+1:]...)
			out = append(out, Variant{
				ID:     next(),
				Kind:   VariantOmit,
				Label:  "skip " + s.Label,
				Steps:  steps,
				Target: s.ID,
			})
		}
	}

	if want[VariantRepeat] {
		for i, s := range chain.Steps {
			if !mutable(s) {
				continue
			}
			steps := make([]string, 0, len(order)+1)
			steps = append(steps, order[:i+1]...)
			steps = append(steps, s.ID)
			steps = append(steps, order[i+1:]...)
			out = append(out, Variant{
				ID:     next(),
				Kind:   VariantRepeat,
				Label:  "repeat " + s.Label,
				Steps:  steps,
				Target: s.ID,
			})
		}
	}

	if want[VariantMove] {
		// Adjacent swaps only. A full permutation sweep is factorial and a
		// distant move is uninterpretable — "step 6 ran before step 2" gives an
		// operator nothing to act on, whereas "confirm ran before validate" does.
		for i := 0; i+1 < len(chain.Steps); i++ {
			a, b := chain.Steps[i], chain.Steps[i+1]
			if !mutable(a) || !mutable(b) {
				continue
			}
			steps := append([]string(nil), order...)
			steps[i], steps[i+1] = steps[i+1], steps[i]
			out = append(out, Variant{
				ID:     next(),
				Kind:   VariantMove,
				Label:  b.Label + " before " + a.Label,
				Steps:  steps,
				Target: b.ID,
			})
		}
	}

	return out
}

// Plan reports how many step instances a set of variants will send, refusing
// before any bytes go on the wire.
//
// Setup steps are counted once per variant because they re-run for each one,
// which is exactly the cost an operator is surprised by otherwise.
func Plan(chain *Chain, variants []Variant) (instances int, err error) {
	if len(chain.Steps) == 0 {
		return 0, fmt.Errorf("chain has no steps")
	}
	if len(variants) == 0 {
		return 0, fmt.Errorf("no variants selected")
	}
	if len(variants) > MaxVariantsPerRun {
		return 0, fmt.Errorf("%d variants exceeds the limit of %d; select fewer mutation kinds", len(variants), MaxVariantsPerRun)
	}
	for _, v := range variants {
		instances += len(v.Steps)
	}
	if instances > MaxInstancesPerRun {
		return 0, fmt.Errorf("%d requests exceeds the limit of %d; select fewer mutation kinds or split the chain", instances, MaxInstancesPerRun)
	}
	return instances, nil
}

// StateChangingMethods reports the non-GET methods a chain would send, for the
// arming gate. Sorted-unique so the warning names each method once.
func StateChangingMethods(chain *Chain) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range chain.Steps {
		m := MethodOf(s.ReqRaw)
		if m == "" || m == "GET" || m == "HEAD" || m == "OPTIONS" {
			continue
		}
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}
