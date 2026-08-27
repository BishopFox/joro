// Package atomicfile writes a file so that an interrupted write leaves the previous
// content rather than a truncated file.
//
// It exists because three of Joro's stores need the same guarantee for the same reason —
// a half-written file is state that fails to load with no obvious cause — and the third
// copy is where duplication stops being deliberate. internal/configstore writes in place,
// which is tolerable for a project config the operator can simply save again; it is not
// what anything referenced by something else should sit behind.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write writes data to path via a temp file and a rename.
//
// The temp file is created with os.CreateTemp, which opens O_EXCL under a name it
// generates. Two properties follow, and both are wanted: the open fails outright rather
// than writing through anything that already sits at that path, and the name is not
// predictable, so it cannot be staked out in advance. A fixed ".tmp" suffix has neither —
// it is guessable, and a plain write to it follows what it finds. The rename is safe
// either way, since it replaces a path rather than resolving through it.
func Write(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating a temp file beside %s: %w", path, err)
	}
	tmp := f.Name()

	// Every failure past this point removes the temp file: a leftover would otherwise
	// accumulate beside the real one on each failed write.
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}

	if _, err := f.Write(data); err != nil {
		return fail(fmt.Errorf("writing %s: %w", tmp, err))
	}
	// CreateTemp opens at 0600; set the requested mode explicitly so the file on disk
	// does not depend on that staying true.
	if err := f.Chmod(perm); err != nil {
		return fail(fmt.Errorf("setting mode on %s: %w", tmp, err))
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("closing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming onto %s: %w", path, err)
	}
	return nil
}
