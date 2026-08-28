package plugins

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"plugin"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/BishopFox/joro/sdk"
)

// sdkModule is the SDK import path, whose version must agree between host and
// plugin. Named here rather than inlined because verifyPluginObject looks it up
// on both sides.
const sdkModule = "github.com/BishopFox/joro/sdk"

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

		manifest, err := safeManifest(lp.ext)
		if err != nil {
			failed = append(failed, loadFailure{filename: name, err: err})
			continue
		}
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

// verifyPluginObject reports why path is not a plugin this binary can load,
// and must be called before plugin.Open.
//
// plugin.Open does not merely return an error on a file it cannot use: for some
// files Go's runtime calls throw(), which no recover() can catch and which takes
// the whole process down. plugin_lastmoduleinit walks the module chain
//
//	for pmd := firstmoduledata.next; pmd != nil; pmd = pmd.next {
//	        if pmd.bad { md = nil; continue }
//	        md = pmd
//	}
//	if md == nil { throw("runtime: no plugin module data") }
//
// so any dlopen that appends no usable Go module is fatal — a file that is not a
// Go object, one built with a buildmode other than plugin, a truncated download,
// or a chain whose tail an earlier rejected load already marked bad. The plugin
// dir is operator-writable and survives an in-app update that replaces the
// binary underneath it, so a file the host can no longer load is the expected
// steady state, not an exotic one. Joro loads plugins before the API server
// starts, so letting one through means a binary that cannot boot at all and an
// operator with no way to reach the UI and delete it.
//
// Everything here is therefore a gate rather than a warning, and rejecting a
// plugin that would in fact have loaded costs a rebuild, where accepting one
// that would not costs the process. Dropping any of these checks re-opens an
// unrecoverable crash.
func verifyPluginObject(path string) error {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		// ReadFile's own wrapper repeats the full path, which the caller already
		// reports as a filename and which does not fit a one-line banner.
		if inner := errors.Unwrap(err); inner != nil {
			err = inner
		}
		return fmt.Errorf("not a Go plugin (no Go build information): %w", err)
	}

	var buildmode string
	for _, s := range bi.Settings {
		if s.Key == "-buildmode" {
			buildmode = s.Value
			break
		}
	}
	// cmd/go records -buildmode unconditionally, so a real plugin always carries
	// it and an empty value means the file was not stamped by `go build` at all.
	if buildmode != "plugin" {
		if buildmode == "" {
			return fmt.Errorf("not built as a Go plugin (no -buildmode recorded); rebuild with `joro --build-plugin <dir> --install`")
		}
		return fmt.Errorf("built with -buildmode=%s, want plugin; rebuild with `joro --build-plugin <dir> --install`", buildmode)
	}

	// Go's own check is a per-package content hash, which an exact version match
	// implies. Comparing version strings instead reports the mismatch in the terms
	// the operator can act on, and does so before dlopen rather than after.
	if bi.GoVersion != runtime.Version() {
		return fmt.Errorf("built with %s, this joro binary is %s; rebuild with `joro --build-plugin <dir> --install`", bi.GoVersion, runtime.Version())
	}

	if hostSDK, ok := hostSDKVersion(); ok {
		if pluginSDK, ok := moduleVersion(bi.Deps, sdkModule); ok && pluginSDK != hostSDK {
			return fmt.Errorf("built against %s %s, this joro binary embeds %s; rebuild with `joro --build-plugin <dir> --install`", sdkModule, pluginSDK, hostSDK)
		}
	}

	return nil
}

// hostSDKVersion returns the SDK version this binary was built against.
func hostSDKVersion() (string, bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", false
	}
	return moduleVersion(info.Deps, sdkModule)
}

// moduleVersion finds a module's effective version in a dependency list,
// following a replace directive to the module that actually got built.
func moduleVersion(deps []*debug.Module, path string) (string, bool) {
	for _, d := range deps {
		if d == nil || d.Path != path {
			continue
		}
		if d.Replace != nil {
			return d.Replace.Version, true
		}
		return d.Version, true
	}
	return "", false
}

func loadOne(path string) (loadedPlugin, error) {
	hash, err := fileHash(path)
	if err != nil {
		return loadedPlugin{}, fmt.Errorf("hash: %w", err)
	}

	if err := verifyPluginObject(path); err != nil {
		return loadedPlugin{}, err
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

// safeManifest calls a plugin's Manifest with panic recovery. It is the first
// call into plugin code on the load path, and it runs before there is a name to
// report the plugin by, so an unguarded panic here takes down startup with a
// stack trace naming no file.
func safeManifest(ext sdk.Plugin) (m sdk.Manifest, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in Manifest: %v", r)
		}
	}()
	return ext.Manifest(), nil
}

// installedPlugins returns the plugin filenames in dir, ignoring everything
// else. A missing dir is not an error: it means no plugins are installed.
func installedPlugins(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		if !entry.IsDir() && isPluginFile(entry.Name()) {
			out = append(out, entry.Name())
		}
	}
	return out
}

// RebuildNotice returns a one-line warning for an operator who has just updated
// Joro, or "" when no plugins are installed.
//
// A plugin is only loadable by the exact toolchain that built the host, so
// replacing the binary invalidates every installed .so — silently, since the
// plugin dir is untouched by an update. Sharing isPluginFile with the loader is
// what keeps the notice and the thing it warns about counting the same files.
func RebuildNotice(dir string) string {
	n := len(installedPlugins(dir))
	if n == 0 {
		return ""
	}
	noun := "plugin"
	if n > 1 {
		noun = "plugins"
	}
	return fmt.Sprintf("Note: %d installed %s must be rebuilt against this version before it will load again: `joro --build-plugin <dir> --install`", n, noun)
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
