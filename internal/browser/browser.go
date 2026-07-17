// Package browser locates an installed Chromium-family browser and launches it
// pointed at the proxy with the proxy CA trusted via an SPKI hash pin.
package browser

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// candidate describes one browser to probe. Exactly one of path/lookup is set:
// path is stat'd directly; lookup is resolved against PATH via exec.LookPath.
type candidate struct {
	name   string
	path   string
	lookup string
}

// Find returns the executable path and display name of the first installed
// Chromium-family browser, probing in the order Chrome, Chromium, Edge, Brave.
func Find() (path, name string, ok bool) {
	for _, c := range candidates() {
		if c.lookup != "" {
			if p, err := exec.LookPath(c.lookup); err == nil {
				return p, c.name, true
			}
			continue
		}
		if info, err := os.Stat(c.path); err == nil && !info.IsDir() {
			return c.path, c.name, true
		}
	}
	return "", "", false
}

func candidates() []candidate {
	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		var out []candidate
		bundles := []struct{ name, rel string }{
			{"Google Chrome", "Google Chrome.app/Contents/MacOS/Google Chrome"},
			{"Chromium", "Chromium.app/Contents/MacOS/Chromium"},
			{"Microsoft Edge", "Microsoft Edge.app/Contents/MacOS/Microsoft Edge"},
			{"Brave", "Brave Browser.app/Contents/MacOS/Brave Browser"},
		}
		for _, b := range bundles {
			out = append(out, candidate{name: b.name, path: filepath.Join("/Applications", b.rel)})
			if home != "" {
				out = append(out, candidate{name: b.name, path: filepath.Join(home, "Applications", b.rel)})
			}
		}
		return out
	case "windows":
		var out []candidate
		progs := []struct{ name, env, rel string }{
			{"Google Chrome", "ProgramFiles", `Google\Chrome\Application\chrome.exe`},
			{"Google Chrome", "ProgramFiles(x86)", `Google\Chrome\Application\chrome.exe`},
			{"Google Chrome", "LocalAppData", `Google\Chrome\Application\chrome.exe`},
			{"Microsoft Edge", "ProgramFiles(x86)", `Microsoft\Edge\Application\msedge.exe`},
			{"Microsoft Edge", "ProgramFiles", `Microsoft\Edge\Application\msedge.exe`},
			{"Brave", "ProgramFiles", `BraveSoftware\Brave-Browser\Application\brave.exe`},
			{"Brave", "ProgramFiles(x86)", `BraveSoftware\Brave-Browser\Application\brave.exe`},
			{"Chromium", "LocalAppData", `Chromium\Application\chrome.exe`},
		}
		for _, p := range progs {
			if base := os.Getenv(p.env); base != "" {
				out = append(out, candidate{name: p.name, path: filepath.Join(base, p.rel)})
			}
		}
		return out
	default:
		return []candidate{
			{name: "Google Chrome", lookup: "google-chrome"},
			{name: "Google Chrome", lookup: "google-chrome-stable"},
			{name: "Chromium", lookup: "chromium"},
			{name: "Chromium", lookup: "chromium-browser"},
			{name: "Microsoft Edge", lookup: "microsoft-edge"},
			{name: "Microsoft Edge", lookup: "microsoft-edge-stable"},
			{name: "Brave", lookup: "brave-browser"},
			{name: "Google Chrome", path: "/opt/google/chrome/chrome"},
			{name: "Chromium", path: "/usr/bin/chromium"},
			{name: "Chromium", path: "/usr/bin/chromium-browser"},
			{name: "Chromium", path: "/snap/bin/chromium"},
		}
	}
}

// SPKIFingerprint returns the base64 SHA-256 of the certificate's DER-encoded
// SubjectPublicKeyInfo, the value expected by --ignore-certificate-errors-spki-list.
func SPKIFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// LaunchOptions configures a browser launch.
type LaunchOptions struct {
	BrowserPath     string
	ProxyAddr       string // host:port of the proxy
	SPKIFingerprint string
	ProfileDir      string
	URL             string
	WipeOnExit      bool // remove ProfileDir once the browser process exits
}

// Launch starts the browser detached, routing all traffic through the proxy and
// trusting only certificates whose SPKI matches SPKIFingerprint.
func Launch(opts LaunchOptions) error {
	if err := os.MkdirAll(opts.ProfileDir, 0700); err != nil {
		return err
	}
	target := opts.URL
	if target == "" {
		target = "about:blank"
	}
	args := []string{
		"--proxy-server=http://" + opts.ProxyAddr,
		"--proxy-bypass-list=<-loopback>",    // route loopback targets through the proxy too
		"--user-data-dir=" + opts.ProfileDir, // the SPKI flag is only honored when a user-data-dir is set
		"--ignore-certificate-errors-spki-list=" + opts.SPKIFingerprint,
		"--test-type", // suppresses the unsupported-command-line-flag infobar; does not alter cert validation
		"--no-first-run",
		"--no-default-browser-check",
		"--new-window",
		// The URL must be last: Chrome treats the first non-switch arg as a URL.
		target,
	}

	cmd := exec.Command(opts.BrowserPath, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	if opts.WipeOnExit {
		// Remove the profile once the browser exits, unless another instance
		// still owns it (a second launch that handed off to the first and
		// exited immediately leaves the first's singleton lock in place).
		dir := opts.ProfileDir
		go func() {
			_ = cmd.Wait()
			if !profileInUse(dir) {
				os.RemoveAll(dir) //nolint:errcheck
			}
		}()
		return nil
	}
	return cmd.Process.Release()
}

// profileInUse reports whether a Chromium instance still holds the profile's
// singleton lock (SingletonLock on Unix, lockfile on Windows).
func profileInUse(profileDir string) bool {
	for _, name := range []string{"SingletonLock", "lockfile"} {
		if _, err := os.Lstat(filepath.Join(profileDir, name)); err == nil {
			return true
		}
	}
	return false
}

// ClearCookies removes the cookie databases from a Chrome profile directory.
// Other site data (history, storage, cache) is left intact. The browser must be
// closed for the removal to take effect, since Chrome holds the DB open while
// running and rewrites it on exit.
func ClearCookies(profileDir string) error {
	rels := []string{
		filepath.Join("Default", "Network", "Cookies"), // current Chrome
		filepath.Join("Default", "Network", "Cookies-journal"),
		filepath.Join("Default", "Cookies"), // legacy path
		filepath.Join("Default", "Cookies-journal"),
		filepath.Join("Default", "Safe Browsing Cookies"),
		filepath.Join("Default", "Safe Browsing Cookies-journal"),
	}
	for _, rel := range rels {
		if err := os.Remove(filepath.Join(profileDir, rel)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
