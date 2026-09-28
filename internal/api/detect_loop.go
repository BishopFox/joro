package api

import "context"

// StartDetectLoop launches the passive detection scanner in the background. It
// runs until ctx is cancelled, mirroring StartAutoSaveLoop.
func (s *APIServer) StartDetectLoop(ctx context.Context) {
	if s.detectScanner == nil {
		return
	}
	// Retained so a rescan can outlive the HTTP request that started it.
	s.mu.Lock()
	s.detectCtx = ctx
	s.mu.Unlock()
	go s.detectScanner.Run(ctx)
}

// detectBackgroundCtx returns the server-lifetime context for rescan jobs,
// falling back to context.Background() when the loop was never started.
func (s *APIServer) detectBackgroundCtx() context.Context {
	s.mu.RLock()
	ctx := s.detectCtx
	s.mu.RUnlock()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// resetDetectCursor moves the live-scan watermark. Must be called wherever
// proxy.Store rewrites its sequence numbering (Clear zeroes nextSeq, LoadItems
// rewrites it); a stale high cursor stops detection for the session.
func (s *APIServer) resetDetectCursor(seq int) {
	// The anomaly engine's record cache is keyed on the same sequence numbering,
	// so it must reset wherever detection's cursor does.
	if s.anomalyEngine != nil {
		s.anomalyEngine.ResetCursor(seq)
	}
	// Reflection mapping walks the same sequence numbering, so it resets here
	// too: this one function is what every reset path calls.
	if s.echoEngine != nil {
		s.echoEngine.ResetCursor(seq)
		if seq == 0 && s.echoStore != nil {
			s.echoStore.Clear()
		}
	}
	if s.detectScanner == nil {
		return
	}
	s.detectScanner.ResetCursor(seq)
}

// clearDetectFindingsWithHistory clears findings alongside request history when
// Config.ClearFindingsWithHistory is set. Off by default.
func (s *APIServer) clearDetectFindingsWithHistory() {
	if s.detectEngine == nil || s.detectFindings == nil {
		return
	}
	if s.detectEngine.Config().ClearFindingsWithHistory {
		s.detectFindings.Clear()
		s.broadcastDetectSummary()
	}
}

// StartEchoLoop launches the reflection mapper. It runs unconditionally and
// no-ops per tick while disabled, so a live toggle needs no restart.
func (s *APIServer) StartEchoLoop(ctx context.Context) {
	if s.echoEngine == nil {
		return
	}
	go s.echoEngine.Run(ctx)
}
