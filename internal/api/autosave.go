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
	// Deciding which project to save and writing it must be one atomic step
	// against a concurrent delete. Reading the active name outside the file lock
	// and passing it to a save that acquires the lock later is what lets a tick
	// that began before a delete write the project back out after it — the file
	// reappears with no sidecar and no way for the operator to tell why.
	s.projectFileMu.Lock()
	defer s.projectFileMu.Unlock()

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
	if err := s.saveProjectLocked(active); err != nil {
		log.Printf("[autosave] failed to save project %q: %v", active, err)
	}
}
