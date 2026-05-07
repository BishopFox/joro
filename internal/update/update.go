package update

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	defaultRemote     = "origin"
	defaultBranch     = "main"
	defaultSourceFile = "main.go"

	githubOwner = "BishopFox"
	githubRepo  = "joro"
)

// versionLiteral matches: var version = "v1.2.3"
var versionLiteral = regexp.MustCompile(`var\s+version\s*=\s*"(v[^"]+)"`)

// InstallMode is how the running binary was installed.
type InstallMode int

const (
	InstallModeUnknown InstallMode = iota
	// InstallModeGit means the binary lives inside a git checkout — updates run
	// `git pull && make build`.
	InstallModeGit
	// InstallModeBinary means the binary is standalone — updates download a
	// goreleaser release archive from GitHub.
	InstallModeBinary
)

// DetectInstallMode returns InstallModeGit if a `.git` directory sits next to
// the running executable, InstallModeBinary otherwise. Returns
// InstallModeUnknown only if the executable path cannot be resolved.
func DetectInstallMode() InstallMode {
	exe, err := os.Executable()
	if err != nil {
		return InstallModeUnknown
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return InstallModeUnknown
	}
	gitDir := filepath.Join(filepath.Dir(exe), ".git")
	if info, err := os.Stat(gitDir); err == nil && info.IsDir() {
		return InstallModeGit
	}
	return InstallModeBinary
}

// CheckForUpdate dispatches on install mode and returns the latest available
// version string and whether it differs from currentVersion. Fails silently on
// any error (no network, no git, malformed response, etc.) so startup is never
// blocked by update-check failures.
func CheckForUpdate(currentVersion string) (latestVersion string, available bool) {
	if currentVersion == "" {
		return "", false
	}

	switch DetectInstallMode() {
	case InstallModeGit:
		return checkForUpdateGit(currentVersion)
	case InstallModeBinary:
		return checkForUpdateBinary(currentVersion)
	default:
		return "", false
	}
}

// checkForUpdateGit refreshes the upstream ref via `git fetch`, reads the
// upstream main.go via `git show`, and compares its embedded version literal
// against the running binary's version.
func checkForUpdateGit(currentVersion string) (string, bool) {
	repoDir, err := RepoDir()
	if err != nil {
		return "", false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fetch := exec.CommandContext(ctx, "git", "-C", repoDir, "fetch", "--quiet", defaultRemote, defaultBranch)
	if err := fetch.Run(); err != nil {
		return "", false
	}

	ref := defaultRemote + "/" + defaultBranch + ":" + defaultSourceFile
	out, err := exec.CommandContext(ctx, "git", "-C", repoDir, "show", ref).Output()
	if err != nil {
		return "", false
	}

	m := versionLiteral.FindSubmatch(out)
	if len(m) < 2 {
		return "", false
	}
	latest := string(m[1])
	if latest == currentVersion {
		return latest, false
	}
	return latest, true
}

// checkForUpdateBinary calls the GitHub releases API for the latest release
// tag and compares it against currentVersion. Fails silently on every error:
// DNS failure, no network, GitHub 4xx/5xx, rate limit (60 req/hr unauth),
// malformed JSON, missing tag_name. Same UX as a missing `git` binary.
func checkForUpdateBinary(currentVersion string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	rel, err := fetchLatestRelease(ctx)
	if err != nil {
		return "", false
	}
	if rel.TagName == "" {
		return "", false
	}
	if rel.TagName == currentVersion {
		return rel.TagName, false
	}
	return rel.TagName, true
}

type githubRelease struct {
	TagName string `json:"tag_name"`
}

func fetchLatestRelease(ctx context.Context) (*githubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", githubOwner, githubRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api status %d", resp.StatusCode)
	}

	var rel githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

// RunUpdate performs an update via whichever install mode is active. The
// progress callback is invoked with status messages.
func RunUpdate(progress func(string)) error {
	switch DetectInstallMode() {
	case InstallModeGit:
		repoDir, err := RepoDir()
		if err != nil {
			return err
		}
		return runGitUpdate(repoDir, progress)
	case InstallModeBinary:
		return runBinaryUpdate(progress)
	default:
		return fmt.Errorf("cannot determine install mode")
	}
}

// runGitUpdate performs a git pull and make build in the given repo directory.
func runGitUpdate(repoDir string, progress func(string)) error {
	progress("Pulling latest changes...")
	pull := exec.Command("git", "-C", repoDir, "pull", "--ff-only")
	pull.Stdout = os.Stdout
	pull.Stderr = os.Stderr
	if err := pull.Run(); err != nil {
		return fmt.Errorf("git pull failed: %w", err)
	}

	progress("Building...")
	build := exec.Command("make", "-C", repoDir, "build")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return fmt.Errorf("make build failed: %w", err)
	}

	return nil
}

// runBinaryUpdate downloads the latest release archive matching the current
// GOOS/GOARCH, verifies its SHA-256 against the release's checksums.txt, and
// atomically replaces the running executable. Caller is expected to invoke
// Restart afterwards.
//
// NOTE: the asset name template here must match archives.name_template in
// .goreleaser.yaml at the repo root. Keep them in sync.
func runBinaryUpdate(progress func(string)) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	progress("Checking latest release...")
	rel, err := fetchLatestRelease(ctx)
	if err != nil {
		return fmt.Errorf("fetch release: %w", err)
	}
	tag := rel.TagName
	if tag == "" {
		return fmt.Errorf("no tag_name in latest release")
	}
	version := strings.TrimPrefix(tag, "v")

	archiveName := fmt.Sprintf("joro_%s_%s_%s", version, runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		archiveName += ".zip"
	} else {
		archiveName += ".tar.gz"
	}
	baseURL := fmt.Sprintf("https://github.com/%s/%s/releases/download/%s", githubOwner, githubRepo, tag)

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	exeDir := filepath.Dir(exe)

	progress("Downloading " + archiveName + "...")
	archivePath := filepath.Join(exeDir, ".joro-update-"+archiveName)
	if err := downloadFile(ctx, baseURL+"/"+archiveName, archivePath); err != nil {
		return fmt.Errorf("download archive: %w", err)
	}
	defer os.Remove(archivePath)

	progress("Verifying checksum...")
	checksumPath := filepath.Join(exeDir, ".joro-update-checksums.txt")
	if err := downloadFile(ctx, baseURL+"/checksums.txt", checksumPath); err != nil {
		return fmt.Errorf("download checksums: %w", err)
	}
	defer os.Remove(checksumPath)

	if err := verifyChecksum(archivePath, archiveName, checksumPath); err != nil {
		return fmt.Errorf("checksum verification: %w", err)
	}

	progress("Extracting...")
	binaryName := "joro"
	if runtime.GOOS == "windows" {
		binaryName = "joro.exe"
	}
	newBinaryPath := filepath.Join(exeDir, ".joro-update-binary")
	if err := extractBinary(archivePath, binaryName, newBinaryPath); err != nil {
		return fmt.Errorf("extract: %w", err)
	}
	// extractBinary leaves the file in place on success; clean up only if
	// replaceBinary fails below.

	progress("Installing...")
	if err := replaceBinary(newBinaryPath, exe); err != nil {
		os.Remove(newBinaryPath)
		return fmt.Errorf("replace binary: %w", err)
	}

	return nil
}

func downloadFile(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d for %s", resp.StatusCode, url)
	}

	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return nil
}

// verifyChecksum reads checksums.txt (format: "<sha256-hex>  <filename>" per
// line) and verifies that archivePath's SHA-256 matches the line for
// archiveName. Returns an error if the file is missing from checksums.txt or
// the hashes differ.
func verifyChecksum(archivePath, archiveName, checksumPath string) error {
	checksums, err := os.ReadFile(checksumPath)
	if err != nil {
		return err
	}
	var want string
	for line := range strings.SplitSeq(string(checksums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == archiveName {
			want = fields[0]
			break
		}
	}
	if want == "" {
		return fmt.Errorf("no checksum entry for %s", archiveName)
	}

	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("checksum mismatch: got %s, want %s", got, want)
	}
	return nil
}

// extractBinary opens archivePath (tar.gz or zip), finds the entry named
// binaryName, and writes it to dest with mode 0755.
func extractBinary(archivePath, binaryName, dest string) error {
	if strings.HasSuffix(archivePath, ".zip") {
		return extractFromZip(archivePath, binaryName, dest)
	}
	return extractFromTarGz(archivePath, binaryName, dest)
}

func extractFromTarGz(archivePath, binaryName, dest string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if filepath.Base(h.Name) != binaryName {
			continue
		}
		return writeBinary(tr, dest)
	}
	return fmt.Errorf("%s not found in archive", binaryName)
}

func extractFromZip(archivePath, binaryName, dest string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer zr.Close()

	for _, zf := range zr.File {
		if filepath.Base(zf.Name) != binaryName {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		return writeBinary(rc, dest)
	}
	return fmt.Errorf("%s not found in archive", binaryName)
}

func writeBinary(r io.Reader, dest string) error {
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, r); err != nil {
		return err
	}
	return nil
}

// replaceBinary atomically swaps newPath into exePath. On unix this is a
// straight rename (the kernel allows replacing a running executable). On
// windows the running exe cannot be deleted, so we move it to exePath+".old"
// first and let the OS clean it up after the next reboot or on best-effort
// removal during a future run.
func replaceBinary(newPath, exePath string) error {
	if runtime.GOOS == "windows" {
		oldPath := exePath + ".old"
		// Best-effort cleanup of any stale .old from a previous update.
		os.Remove(oldPath)
		if err := os.Rename(exePath, oldPath); err != nil {
			return err
		}
		if err := os.Rename(newPath, exePath); err != nil {
			// Try to roll back so the old binary is still in place.
			_ = os.Rename(oldPath, exePath)
			return err
		}
		return nil
	}
	return os.Rename(newPath, exePath)
}

// Restart replaces the current process with the same binary and arguments.
func Restart() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot find executable path: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("cannot resolve executable symlinks: %w", err)
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}

// RepoDir returns the repository directory by resolving the binary's location
// and verifying a .git directory exists there.
func RepoDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot find executable path: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("cannot resolve executable symlinks: %w", err)
	}
	dir := filepath.Dir(exe)

	gitDir := filepath.Join(dir, ".git")
	if info, err := os.Stat(gitDir); err != nil || !info.IsDir() {
		return "", fmt.Errorf("binary is not in a git repository (no .git in %s)", dir)
	}
	return dir, nil
}
