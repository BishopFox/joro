package inject

import "context"

// Drive iterates every parameter of every request, calling probe with the point
// and that request's baseline. It handles enumeration, per-request baselining,
// cancellation, and progress (one tick per request, matching the run's URL-based
// total). Finding-reporting stays in probe (this package does not import
// activescan), which is why probe takes no reporter.
func Drive(ctx context.Context, reqs [][]byte, s *Sender, progress func(delta int), probe func(ctx context.Context, p Point, base *Baseline)) {
	for _, raw := range reqs {
		if ctx.Err() != nil {
			return
		}
		base, err := s.Baseline(ctx, raw)
		if err != nil {
			if progress != nil {
				progress(1)
			}
			continue
		}
		for _, p := range Enumerate(raw) {
			if ctx.Err() != nil {
				return
			}
			probe(ctx, p, base)
		}
		if progress != nil {
			progress(1)
		}
	}
}
