package configstore

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var validName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Store handles reading and writing named configuration files.
type Store struct {
	dataDir string
}

// NewStore creates a Store rooted at the given data directory.
func NewStore(dataDir string) *Store {
	return &Store{dataDir: dataDir}
}

// dir returns the directory for the given config type.
func (s *Store) dir(configType string) string {
	return filepath.Join(s.dataDir, "configs", configType)
}

// ValidateName checks that a config name is safe for use as a filename.
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("config name must not be empty")
	}
	if !validName.MatchString(name) {
		return fmt.Errorf("config name must contain only letters, digits, hyphens, and underscores")
	}
	return nil
}

// List returns the names of all saved configs of the given type.
func (s *Store) List(configType string) ([]string, error) {
	dir := s.dir(configType)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	seen := make(map[string]struct{})
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		var cut string
		var ok bool
		if cut, ok = strings.CutSuffix(n, ".joro"); !ok {
			cut, ok = strings.CutSuffix(n, ".json")
		}
		if ok {
			if _, dup := seen[cut]; !dup {
				seen[cut] = struct{}{}
				names = append(names, cut)
			}
		}
	}
	if names == nil {
		names = []string{}
	}
	return names, nil
}

// Save writes data as a named config file.
func (s *Store) Save(configType, name string, data []byte) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	dir := s.dir(configType)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".json"), data, 0o600)
}

// Load reads a named config file and returns its contents.
func (s *Store) Load(configType, name string) ([]byte, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(s.dir(configType), name+".json"))
}

// SaveGzip writes gzip-compressed data as a .joro config file and removes any stale .json file.
func (s *Store) SaveGzip(configType, name string, data []byte) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	dir := s.dir(configType)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, name+".joro"), data, 0o600); err != nil {
		return err
	}
	// Remove stale .json if it exists.
	_ = os.Remove(filepath.Join(dir, name+".json"))
	return nil
}

// LoadAny tries to load a config by name, preferring .joro then falling back to .json.
func (s *Store) LoadAny(configType, name string) ([]byte, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	dir := s.dir(configType)
	data, err := os.ReadFile(filepath.Join(dir, name+".joro"))
	if err == nil {
		return data, nil
	}
	return os.ReadFile(filepath.Join(dir, name+".json"))
}

// DeleteAll removes both .joro and .json files for a named config.
// Returns an error only if neither file existed.
func (s *Store) DeleteAll(configType, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	dir := s.dir(configType)
	errJoro := os.Remove(filepath.Join(dir, name+".joro"))
	errJSON := os.Remove(filepath.Join(dir, name+".json"))
	if errJoro != nil && os.IsNotExist(errJoro) && errJSON != nil && os.IsNotExist(errJSON) {
		return fmt.Errorf("config %q not found", name)
	}
	return nil
}

// Delete removes a named config file.
func (s *Store) Delete(configType, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	path := filepath.Join(s.dir(configType), name+".json")
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("config %q not found", name)
		}
		return err
	}
	return nil
}
