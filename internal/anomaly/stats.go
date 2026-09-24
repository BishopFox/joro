package anomaly

import "sort"

// median returns the median of xs. It sorts a copy, so the caller's slice is
// untouched. An empty slice returns 0.
func median(xs []float64) float64 {
	n := len(xs)
	if n == 0 {
		return 0
	}
	c := make([]float64, n)
	copy(c, xs)
	sort.Float64s(c)
	if n%2 == 1 {
		return c[n/2]
	}
	return (c[n/2-1] + c[n/2]) / 2
}

// mad is the median absolute deviation from med — a spread measure that, unlike
// the standard deviation, is not itself dragged toward the outliers this package
// hunts for.
func mad(xs []float64, med float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	dev := make([]float64, len(xs))
	for i, x := range xs {
		d := x - med
		if d < 0 {
			d = -d
		}
		dev[i] = d
	}
	return median(dev)
}

// robustZ is the MAD-based z-score. 0.6745 rescales the MAD to a standard-
// deviation-equivalent for normal data, so a threshold of ~3.5 has the usual
// reading. Returns 0 when the spread is degenerate (every value identical),
// which correctly flags nothing.
func robustZ(x, med, madv float64) float64 {
	if madv <= 0 {
		return 0
	}
	z := 0.6745 * (x - med) / madv
	if z < 0 {
		z = -z
	}
	return z
}

// modalStr returns the most frequent key in m and its count, ties broken by the
// lexically smaller key so the result is stable across runs.
func modalStr(m map[string]int) (string, int) {
	best := ""
	bestN := 0
	for k, v := range m {
		if v > bestN || (v == bestN && k < best) {
			best = k
			bestN = v
		}
	}
	return best, bestN
}

// modalInt is modalStr for integer keys.
func modalInt(m map[int]int) (int, int) {
	best := 0
	bestN := 0
	first := true
	for k, v := range m {
		if first || v > bestN || (v == bestN && k < best) {
			best = k
			bestN = v
			first = false
		}
	}
	return best, bestN
}
