//go:build !unix

package main

// isForeground is a no-op on platforms without SIGTTIN semantics (Windows).
func isForeground() bool {
	return true
}
