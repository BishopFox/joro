package chain

import (
	"fmt"
	"sort"
	"strings"
)

// Validate checks a chain on the write path.
//
// Write path only, never on read. A chain that a hand-edited project file pushed
// past a bound still has to load, so the operator can see it and fix it —
// refusing it at load would make the workflow vanish rather than report itself,
// which is the polarity internal/trigger's store and jsautomation's validateFlow
// both settled on.
func Validate(c *Chain) error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("chain needs a name")
	}
	if len(c.Name) > MaxNameLen {
		return fmt.Errorf("name is over %d characters", MaxNameLen)
	}
	if len(c.Steps) == 0 {
		return fmt.Errorf("chain has no steps")
	}
	if len(c.Steps) > MaxSteps {
		return fmt.Errorf("%d steps exceeds the limit of %d", len(c.Steps), MaxSteps)
	}
	if len(c.Bindings) > MaxBindings {
		return fmt.Errorf("%d bindings exceeds the limit of %d", len(c.Bindings), MaxBindings)
	}

	index := make(map[string]int, len(c.Steps))
	for i, s := range c.Steps {
		if s.ID == "" {
			return fmt.Errorf("step %d has no id", i+1)
		}
		if _, dup := index[s.ID]; dup {
			return fmt.Errorf("duplicate step id %q", s.ID)
		}
		index[s.ID] = i

		if len(s.ReqRaw) == 0 {
			return fmt.Errorf("step %q has no request bytes", s.Label)
		}
		if len(s.ReqRaw) > MaxStepBytes {
			return fmt.Errorf("step %q request is %d bytes, over the %d byte limit", s.Label, len(s.ReqRaw), MaxStepBytes)
		}
		if len(s.RespRaw) > MaxStepRespBytes {
			return fmt.Errorf("step %q response is %d bytes, over the %d byte limit", s.Label, len(s.RespRaw), MaxStepRespBytes)
		}
		if strings.TrimSpace(s.Host) == "" {
			return fmt.Errorf("step %q has no host", s.Label)
		}
		if MethodOf(s.ReqRaw) == "" {
			return fmt.Errorf("step %q does not start with a request line", s.Label)
		}
	}

	if c.GoalStepID != "" {
		if _, ok := index[c.GoalStepID]; !ok {
			return fmt.Errorf("goal step %q is not in the chain", c.GoalStepID)
		}
	}

	seenBinding := map[string]bool{}
	spansByStep := map[string][]Span{}
	for _, b := range c.Bindings {
		if b.ID == "" {
			return fmt.Errorf("binding for %q has no id", b.Var)
		}
		if seenBinding[b.ID] {
			return fmt.Errorf("duplicate binding id %q", b.ID)
		}
		seenBinding[b.ID] = true

		if strings.TrimSpace(b.Var) == "" {
			return fmt.Errorf("binding %s has no variable name", b.ID)
		}
		if len(b.Var) > MaxVarLen {
			return fmt.Errorf("variable name %q is over %d characters", b.Var, MaxVarLen)
		}
		from, okFrom := index[b.FromStep]
		if !okFrom {
			return fmt.Errorf("binding %q reads from step %q, which is not in the chain", b.Var, b.FromStep)
		}
		to, okTo := index[b.ToStep]
		if !okTo {
			return fmt.Errorf("binding %q writes to step %q, which is not in the chain", b.Var, b.ToStep)
		}

		// A binding pointing backwards is not merely useless, it is a promise
		// the run can never keep: the producer has not run when the consumer
		// needs it, so every variant would report the dependency unresolved.
		// Reordering is what the feature does, so this is checked against the
		// chain's own order rather than any particular variant.
		if from >= to {
			return fmt.Errorf("binding %q reads from %q, which does not run before %q",
				b.Var, c.Steps[from].Label, c.Steps[to].Label)
		}

		if err := validateSource(b.Source, b.Var); err != nil {
			return err
		}
		if b.OnMissing != "" && b.OnMissing != MissingFail && b.OnMissing != MissingRecorded {
			return fmt.Errorf("binding %q has an unknown onMissing %q", b.Var, b.OnMissing)
		}
		if len(b.Spans) == 0 {
			return fmt.Errorf("binding %q has nowhere to write its value", b.Var)
		}
		if len(b.Spans) > MaxSpansPerBinding {
			return fmt.Errorf("binding %q writes to %d places, over the limit of %d", b.Var, len(b.Spans), MaxSpansPerBinding)
		}
		limit := len(c.Steps[to].ReqRaw)
		for _, sp := range b.Spans {
			if sp.Start < 0 || sp.End > limit || sp.Start >= sp.End {
				return fmt.Errorf("binding %q has a span outside %q's recorded request", b.Var, c.Steps[to].Label)
			}
		}
		spansByStep[b.ToStep] = append(spansByStep[b.ToStep], b.Spans...)
	}

	// Overlapping spans in one step have no defined result: Render applies them
	// descending, so an overlap would have one substitution eat part of another
	// and emit bytes belonging to neither.
	for stepID, spans := range spansByStep {
		sort.Slice(spans, func(i, j int) bool { return spans[i].Start < spans[j].Start })
		for i := 1; i < len(spans); i++ {
			if spans[i].Start < spans[i-1].End {
				label := stepID
				if s, _, ok := c.StepByID(stepID); ok {
					label = s.Label
				}
				return fmt.Errorf("two bindings write to overlapping bytes of %q", label)
			}
		}
	}

	return nil
}

func validateSource(s Source, varName string) error {
	switch s.Kind {
	case SourceHeader, SourceCookie:
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("binding %q needs a %s name", varName, s.Kind)
		}
	case SourceJSON:
		if strings.TrimSpace(s.Path) == "" {
			return fmt.Errorf("binding %q needs a json path", varName)
		}
	case SourceRegex:
		if strings.TrimSpace(s.Expr) == "" {
			return fmt.Errorf("binding %q needs a pattern", varName)
		}
		if s.Group < 0 {
			return fmt.Errorf("binding %q has a negative capture group", varName)
		}
	case SourceBetween:
		if s.Prefix == "" {
			return fmt.Errorf("binding %q needs text to anchor on", varName)
		}
	default:
		return fmt.Errorf("binding %q has an unknown source kind %q", varName, s.Kind)
	}
	return nil
}
