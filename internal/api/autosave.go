package api

import (
	"context"
	"log"
	"time"
)

// autoSaveInterval is how often the auto-save loop checks the active project for
// changes.
const autoSaveInterval = 30 * time.Second

// StartAutoSaveLoop launches a background goroutine that periodically saves the
// active project when its autoSave preference is on and the live state has
// changed since the last save. It runs until ctx is cancelled.
func (s *APIServer) StartAutoSaveLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(autoSaveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.autoSaveTick()
			}
		}
	}()
}

// autoSaveTick performs one auto-save check. It is a no-op when no project is
// active, the active project has autoSave disabled, or nothing changed since the
// last save.
func (s *APIServer) autoSaveTick() {
	s.mu.RLock()
	active := s.activeProjectConfig
	lastSig := s.lastSaveSig
	s.mu.RUnlock()
	if active == "" {
		return
	}
	if autoSave, _ := s.resolveProjectPrefs(active); !autoSave {
		return
	}
	if s.liveStateSignature() == lastSig {
		return
	}
	if err := s.saveProject(active); err != nil {
		log.Printf("[autosave] failed to save project %q: %v", active, err)
	}
}
