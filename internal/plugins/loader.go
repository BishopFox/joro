package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"plugin"
	"regexp"
	"strings"

	"github.com/BishopFox/joro/sdk"
)

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// reservedNames may not be used as plugin names because they conflict
// with built-in URL path segments.
var reservedNames = map[string]bool{
	"api": true, "ws": true, "ext": true, "system": true,
}

// loadedPlugin holds one successfully loaded plugin.
type loadedPlugin struct {
	ext      sdk.Plugin
	hash     string // SHA-256 hex of the .so file
	filename string // original filename, e.g. "my-plugin.so"
}

// loadFailure is a plugin file that could not be loaded, carried out of the
// loader rather than only logged.
//
// The operator has to be able to name the file to delete it, and a file that
// fails to load is the one most likely to need deleting: a plugin built against
// a different toolchain than the host is rejected by dlopen and will fail again
// on every start. A list of successful loads is exactly what hides it, leaving
// no way to remove it short of a shell.
type loadFailure struct {
	filename string
	err      error
}

// loadPlugins scans dir for .so/.dylib files, opens each via Go's plugin
// package, and looks up the exported "Extension" symbol. Per-file problems come
// back as failures (one per file, with its name); the []error return is for
// directory-level problems, which belong to no single file.
func loadPlugins(dir string) ([]loadedPlugin, []loadFailure, []error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, []error{fmt.Errorf("read plugin dir: %w", err)}
	}

	var loaded []loadedPlugin
	var failed []loadFailure
	seen := map[string]bool{}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isPluginFile(name) {
			continue
		}

		path := filepath.Join(dir, name)
		lp, err := loadOne(path)
		if err != nil {
			failed = append(failed, loadFailure{filename: name, err: err})
			continue
		}
		lp.filename = name

		manifest := lp.ext.Manifest()
		if err := validateManifest(manifest); err != nil {
			failed = append(failed, loadFailure{filename: name, err: err})
			continue
		}

		if seen[manifest.Name] {
			failed = append(failed, loadFailure{
				filename: name,
				err:      fmt.Errorf("duplicate name %q", manifest.Name),
			})
			continue
		}
		seen[manifest.Name] = true
		loaded = append(loaded, lp)
	}

	return loaded, failed, nil
}

func loadOne(path string) (loadedPlugin, error) {
	hash, err := fileHash(path)
	if err != nil {
		return loadedPlugin{}, fmt.Errorf("hash: %w", err)
	}

	p, err := plugin.Open(path)
	if err != nil {
		// "plugin: not implemented" surfaces when the host binary was built
		// with CGO_ENABLED=0 — Go's plugin runtime is dlopen-based and gets
		// compiled out. Re-skin the error with actionable guidance.
		if strings.Contains(err.Error(), "plugin: not implemented") {
			return loadedPlugin{}, fmt.Errorf("Go plugin support is disabled in this joro binary (built without CGO). Install a release v1.0.1 or later, or build from source with `make build`")
		}
		return loadedPlugin{}, fmt.Errorf("open: %w", err)
	}

	sym, err := p.Lookup("Plugin")
	if err != nil {
		return loadedPlugin{}, fmt.Errorf("lookup Plugin symbol: %w", err)
	}

	// The symbol must be a pointer to an sdk.Plugin value.
	plugPtr, ok := sym.(*sdk.Plugin)
	if !ok {
		return loadedPlugin{}, fmt.Errorf("Plugin symbol is %T, want *sdk.Plugin", sym)
	}

	return loadedPlugin{ext: *plugPtr, hash: hash}, nil
}

func isPluginFile(name string) bool {
	return strings.HasSuffix(name, ".so") || strings.HasSuffix(name, ".dylib")
}

func validateManifest(m sdk.Manifest) error {
	if !nameRe.MatchString(m.Name) {
		return fmt.Errorf("invalid name %q: must match %s", m.Name, nameRe.String())
	}
	if reservedNames[m.Name] {
		return fmt.Errorf("reserved name %q", m.Name)
	}
	switch m.Type {
	case sdk.TypeExecProvider, sdk.TypeTab, sdk.TypeFeature, sdk.TypeProxyHook, sdk.TypeDashboard, sdk.TypeInteractProvider:
		// valid
	default:
		return fmt.Errorf("unknown plugin type %q", m.Type)
	}
	return nil
}

func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
