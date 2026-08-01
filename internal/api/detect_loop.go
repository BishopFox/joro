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
