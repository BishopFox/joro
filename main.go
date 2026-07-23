package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	flag "github.com/spf13/pflag"

	"github.com/BishopFox/joro/internal/api"
	"github.com/BishopFox/joro/internal/callback"
	"github.com/BishopFox/joro/internal/cert"
	"github.com/BishopFox/joro/internal/config"
	"github.com/BishopFox/joro/internal/notes"
	"github.com/BishopFox/joro/internal/plugins"
	"github.com/BishopFox/joro/internal/proxy"
	"github.com/BishopFox/joro/internal/team"
	"github.com/BishopFox/joro/internal/update"
	"github.com/BishopFox/joro/internal/xsshunter"
)

var version = "v1.7.0"
var commit = "dev" // injected via -ldflags at build time

func main() {
	cfg := config.Default()

	flag.IntVar(&cfg.ProxyPort, "proxy-port", cfg.ProxyPort, "Port for the intercepting proxy")
	flag.IntVar(&cfg.UIPort, "ui-port", cfg.UIPort, "Port for the web UI and API")
	flag.StringVar(&cfg.DataDir, "data-dir", cfg.DataDir, "Directory for CA certs and data")
	flag.BoolVar(&cfg.Dev, "dev", false, "Reverse-proxy UI requests to Vite dev server (enables HMR)")
	flag.StringVar(&cfg.ViteURL, "vite-url", cfg.ViteURL, "Vite dev server URL (used with --dev)")
	flag.BoolVar(&cfg.Listener, "listener", false, "Run in listener mode (callback server, no proxy)")
	flag.IntVar(&cfg.CallbackDNSPort, "dns-port", cfg.CallbackDNSPort, "DNS listener port (listener mode)")
	flag.IntVar(&cfg.CallbackHTTPPort, "http-port", cfg.CallbackHTTPPort, "HTTP callback listener port (listener mode)")
	flag.IntVar(&cfg.CallbackHTTPSPort, "https-port", cfg.CallbackHTTPSPort, "HTTPS callback listener port (listener mode, 0 to disable)")
	flag.IntVar(&cfg.CallbackSMTPPort, "smtp-port", cfg.CallbackSMTPPort, "SMTP callback listener port (listener mode, 0 to disable)")
	flag.IntVar(&cfg.CallbackSMTPSPort, "smtps-port", cfg.CallbackSMTPSPort, "SMTPS (implicit TLS) callback listener port (listener mode, 0 to disable)")
	flag.IntVar(&cfg.CallbackFTPPort, "ftp-port", cfg.CallbackFTPPort, "FTP callback listener port (listener mode, 0 to disable)")
	flag.IntVar(&cfg.CallbackFTPSPort, "ftps-port", cfg.CallbackFTPSPort, "FTPS (implicit TLS) callback listener port (listener mode, 0 to disable)")
	flag.IntVar(&cfg.CallbackLDAPPort, "ldap-port", cfg.CallbackLDAPPort, "LDAP callback listener port (listener mode, 0 to disable)")
	flag.IntVar(&cfg.CallbackLDAPSPort, "ldaps-port", cfg.CallbackLDAPSPort, "LDAPS (implicit TLS) callback listener port (listener mode, 0 to disable)")
	flag.StringVar(&cfg.TLSCertFile, "tls-cert", cfg.TLSCertFile, "Path to PEM-encoded TLS certificate for the HTTPS/SMTPS/FTPS/LDAPS callback listeners (listener mode). If set, replaces the auto-generated self-signed cert. Must be set together with --tls-key.")
	flag.StringVar(&cfg.TLSKeyFile, "tls-key", cfg.TLSKeyFile, "Path to PEM-encoded TLS private key for the HTTPS/SMTPS/FTPS/LDAPS callback listeners (listener mode). Must be set together with --tls-cert.")
	flag.StringVar(&cfg.CallbackDomain, "domain", cfg.CallbackDomain, "Callback domain (listener mode)")
	flag.StringVar(&cfg.CallbackResponseIP, "response-ip", cfg.CallbackResponseIP, "IP address returned in DNS A responses (listener mode)")
	flag.StringVar(&cfg.BindAddr, "bind", cfg.BindAddr, "Address to bind servers to (in proxy mode this governs the proxy port only; the UI/API is always loopback-only)")
	flag.StringSliceVar(&cfg.AllowedHosts, "allowed-host", cfg.AllowedHosts, "Additional Host header value(s) accepted by the proxy-mode UI/API origin guard, beyond loopback (e.g. an SSH tunnel entry address). Comma-separated or repeatable. Same-origin CSRF checks still apply.")
	flag.BoolVar(&cfg.TeamServer, "teamserver", false, "Enable team server mode (requires --listener)")
	flag.BoolVar(&cfg.DisableUpdateChecks, "disable-update-checks", false, "Disable automatic update checks at startup and in the background (can also be toggled in Settings)")

	buildPlugin := flag.String("build-plugin", "", "Build a plugin from the given directory and exit")
	installPlugin := flag.Bool("install", false, "Copy built plugin to ~/.joro/plugins/ (use with --build-plugin)")
	outputPath := flag.StringP("output", "o", "", "Output path for built plugin (use with --build-plugin)")
	showVersion := flag.BoolP("version", "v", false, "Print version and exit")
	flag.Parse()

	// Listener mode defaults to 0.0.0.0 (needs external callbacks) unless --bind was explicitly set.
	if cfg.Listener && !flag.CommandLine.Changed("bind") {
		cfg.BindAddr = "0.0.0.0"
	}

	if cfg.BindAddr != "127.0.0.1" && cfg.BindAddr != "localhost" && cfg.BindAddr != "::1" {
		what := "servers"
		if !cfg.Listener {
			// Proxy mode forces the UI/API to loopback; only the proxy port honors --bind.
			what = "the proxy port"
		}
		fmt.Fprintf(os.Stderr, "WARNING: Binding to %s — %s will be accessible from the network.\n", cfg.BindAddr, what)
	}

	if *showVersion {
		fmt.Printf("%s (%s)\n", version, commit)
		os.Exit(0)
	}

	if *buildPlugin != "" {
		os.Exit(runBuildPlugin(*buildPlugin, *outputPath, *installPlugin, cfg.DataDir))
	}

	ctx := context.Background()

	if cfg.TeamServer && !cfg.Listener {
		fmt.Fprintln(os.Stderr, "error: --teamserver requires --listener")
		os.Exit(1)
	}

	if cfg.Listener {
		runListenerMode(ctx, cfg)
	} else {
		runProxyMode(ctx, cfg)
	}
}

func runListenerMode(ctx context.Context, cfg config.Config) {
	// Ensure data directory exists.
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatalf("data dir: %v", err)
	}

	dbPath := filepath.Join(cfg.DataDir, "callbacks.db")
	db, err := callback.OpenDB(dbPath)
	if err != nil {
		log.Fatalf("callback DB: %v", err)
	}
	defer db.Close()

	cbStore := callback.NewStore(db)
	xssStore := xsshunter.NewStore(db)

	// Set config from flags (always overrides DB values).
	if cfg.CallbackDomain != "" {
		responseIP := cfg.CallbackResponseIP
		if responseIP == "" {
			responseIP = "127.0.0.1"
		}
		cbStore.SetConfig(&callback.CallbackConfig{ //nolint:errcheck
			Domain:     cfg.CallbackDomain,
			ResponseIP: responseIP,
		})
	}

	hub := api.NewHub()
	go hub.Run()

	// Start DNS server.
	dnsSrv := callback.NewDNSServer(cbStore, hub.Broadcast(), cfg.BindAddr, cfg.CallbackDNSPort)
	go func() {
		fmt.Printf("DNS callback listener on %s:%d\n", cfg.BindAddr, cfg.CallbackDNSPort)
		if err := dnsSrv.Start(ctx); err != nil {
			log.Printf("DNS server: %v", err)
		}
	}()

	// Build shared TLS config if any TLS-capable listener is enabled.
	needsTLS := cfg.CallbackHTTPSPort > 0 || cfg.CallbackSMTPSPort > 0 ||
		cfg.CallbackFTPSPort > 0 || cfg.CallbackLDAPSPort > 0 ||
		cfg.TLSCertFile != "" || cfg.TLSKeyFile != ""
	var tlsCfg *tls.Config
	if needsTLS {
		tlsCfg = buildCallbackTLSConfig(cfg)
	}
	if cfg.CallbackSMTPSPort > 0 && tlsCfg == nil {
		log.Fatalf("--smtps-port requires TLS — supply --tls-cert/--tls-key or enable --https-port")
	}
	if cfg.CallbackFTPSPort > 0 && tlsCfg == nil {
		log.Fatalf("--ftps-port requires TLS — supply --tls-cert/--tls-key or enable --https-port")
	}
	if cfg.CallbackLDAPSPort > 0 && tlsCfg == nil {
		log.Fatalf("--ldaps-port requires TLS — supply --tls-cert/--tls-key or enable --https-port")
	}

	// Start HTTP callback server.
	httpSrv := callback.NewHTTPServer(cbStore, xssStore, hub.Broadcast(), cfg.BindAddr, cfg.CallbackHTTPPort)
	if cfg.CallbackHTTPSPort > 0 {
		httpSrv.WithTLS(tlsCfg, cfg.CallbackHTTPSPort)
	}

	go func() {
		fmt.Printf("HTTP callback listener on %s:%d\n", cfg.BindAddr, cfg.CallbackHTTPPort)
		if cfg.CallbackHTTPSPort > 0 {
			fmt.Printf("HTTPS callback listener on %s:%d\n", cfg.BindAddr, cfg.CallbackHTTPSPort)
		}
		if err := httpSrv.Start(ctx); err != nil {
			log.Printf("HTTP(S) callback server: %v", err)
		}
	}()

	// Start SMTP callback server.
	if cfg.CallbackSMTPPort > 0 || cfg.CallbackSMTPSPort > 0 {
		smtpSrv := callback.NewSMTPServer(cbStore, hub.Broadcast(), cfg.BindAddr,
			cfg.CallbackSMTPPort, cfg.CallbackSMTPSPort, tlsCfg)
		go func() {
			if cfg.CallbackSMTPPort > 0 {
				fmt.Printf("SMTP callback listener on %s:%d\n", cfg.BindAddr, cfg.CallbackSMTPPort)
			}
			if cfg.CallbackSMTPSPort > 0 {
				fmt.Printf("SMTPS callback listener on %s:%d\n", cfg.BindAddr, cfg.CallbackSMTPSPort)
			}
			if err := smtpSrv.Start(ctx); err != nil {
				log.Printf("SMTP server: %v", err)
			}
		}()
	}

	// Start FTP callback server.
	if cfg.CallbackFTPPort > 0 || cfg.CallbackFTPSPort > 0 {
		ftpSrv := callback.NewFTPServer(cbStore, hub.Broadcast(), cfg.BindAddr,
			cfg.CallbackFTPPort, cfg.CallbackFTPSPort, tlsCfg)
		go func() {
			if cfg.CallbackFTPPort > 0 {
				fmt.Printf("FTP callback listener on %s:%d\n", cfg.BindAddr, cfg.CallbackFTPPort)
			}
			if cfg.CallbackFTPSPort > 0 {
				fmt.Printf("FTPS callback listener on %s:%d\n", cfg.BindAddr, cfg.CallbackFTPSPort)
			}
			if err := ftpSrv.Start(ctx); err != nil {
				log.Printf("FTP server: %v", err)
			}
		}()
	}

	// Start LDAP callback server.
	if cfg.CallbackLDAPPort > 0 || cfg.CallbackLDAPSPort > 0 {
		ldapSrv := callback.NewLDAPServer(cbStore, hub.Broadcast(), cfg.BindAddr,
			cfg.CallbackLDAPPort, cfg.CallbackLDAPSPort, tlsCfg)
		go func() {
			if cfg.CallbackLDAPPort > 0 {
				fmt.Printf("LDAP callback listener on %s:%d\n", cfg.BindAddr, cfg.CallbackLDAPPort)
			}
			if cfg.CallbackLDAPSPort > 0 {
				fmt.Printf("LDAPS callback listener on %s:%d\n", cfg.BindAddr, cfg.CallbackLDAPSPort)
			}
			if err := ldapSrv.Start(ctx); err != nil {
				log.Printf("LDAP server: %v", err)
			}
		}()
	}

	// Generate auth token for listener API access.
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		log.Fatalf("generate auth token: %v", err)
	}
	token := hex.EncodeToString(tokenBytes)
	fmt.Printf("[LISTENER] Auth token: %s\n", token)

	// Start API server.
	var apiSrv *api.APIServer
	if cfg.TeamServer {
		if err := team.MigrateDB(db); err != nil {
			log.Fatalf("team DB migration: %v", err)
		}
		teamStore := team.NewStore(db)

		apiSrv = api.NewTeamServerMode(cfg, cbStore, xssStore, hub, teamStore, token)
	} else {
		apiSrv = api.NewListenerMode(cfg, cbStore, xssStore, hub, token)
	}
	fmt.Printf("Callback API available at http://%s:%d\n", cfg.BindAddr, cfg.UIPort)
	if err := apiSrv.Start(ctx); err != nil {
		log.Fatalf("API server: %v", err)
	}
}

// buildCallbackTLSConfig returns the TLS config shared by all callback
// listeners (HTTPS, SMTPS, STARTTLS). External cert+key via --tls-cert/--tls-key
// takes precedence; otherwise a leaf is generated from Joro's CA.
func buildCallbackTLSConfig(cfg config.Config) *tls.Config {
	switch {
	case cfg.TLSCertFile != "" && cfg.TLSKeyFile != "":
		extCert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			log.Fatalf("load external TLS cert: %v", err)
		}
		fmt.Printf("Using external TLS cert: %s\n", cfg.TLSCertFile)
		return &tls.Config{Certificates: []tls.Certificate{extCert}}
	case cfg.TLSCertFile != "" || cfg.TLSKeyFile != "":
		log.Fatalf("--tls-cert and --tls-key must be set together")
		return nil
	default:
		ca, err := cert.LoadOrCreate(cfg.DataDir)
		if err != nil {
			log.Fatalf("CA init: %v", err)
		}
		names := []string{"localhost"}
		if cfg.CallbackDomain != "" {
			names = []string{cfg.CallbackDomain, "*." + cfg.CallbackDomain}
		}
		leafCert, err := cert.GenerateLeafMulti(ca, names)
		if err != nil {
			log.Fatalf("callback TLS cert: %v", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{*leafCert}}
	}
}

func runProxyMode(ctx context.Context, cfg config.Config) {
	// Check for updates (proxy mode only, unless disabled).
	var updateAvailable bool
	var latestVersion string
	if !cfg.DisableUpdateChecks {
		fmt.Println("Checking for updates...")
		latestVersion, updateAvailable = update.CheckForUpdate(version)
		if updateAvailable {
			// Skip the prompt if stdin is redirected (pipe, /dev/null, service
			// manager) or if we're in the background process group — reading the
			// controlling tty from a background group delivers SIGTTIN and stops
			// the process, which would leave the proxy and UI unstarted.
			stat, err := os.Stdin.Stat()
			if err != nil || (stat.Mode()&os.ModeCharDevice) == 0 || !isForeground() {
				fmt.Printf("An update is available (latest: %s). Run interactively to update, or use the web UI.\n", latestVersion)
			} else {
				fmt.Printf("An update is available (latest: %s). Update now? [Y/n] ", latestVersion)
				reader := bufio.NewReader(os.Stdin)
				answer, _ := reader.ReadString('\n')
				answer = strings.TrimSpace(strings.ToLower(answer))
				if answer == "" || answer == "y" || answer == "yes" {
					if err := update.RunUpdate(func(msg string) { fmt.Println(msg) }); err != nil {
						log.Printf("Update failed: %v", err)
					} else {
						fmt.Println("Restarting...")
						if err := update.Restart(); err != nil {
							log.Fatalf("Restart failed: %v", err)
						}
					}
				}
			}
		} else {
			fmt.Println("Already up to date.")
		}
	}

	// Ensure data directory exists.
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatalf("data dir: %v", err)
	}

	// Load or generate the CA certificate.
	ca, err := cert.LoadOrCreate(cfg.DataDir)
	if err != nil {
		log.Fatalf("CA init: %v", err)
	}

	// Open local DB for notes.
	localDB, err := notes.OpenDB(filepath.Join(cfg.DataDir, "joro.db"))
	if err != nil {
		log.Fatalf("local DB: %v", err)
	}
	defer localDB.Close()
	noteStore := notes.NewStore(localDB)

	// Shared components.
	certCache := cert.NewCache(ca)
	store := proxy.NewStore(5000)
	interceptQ := proxy.NewInterceptQueue(0) // default 60s timeout
	scope := proxy.NewScope()

	noise := proxy.NewNoiseFilter()
	replace := proxy.NewMatchReplace()
	customData := proxy.NewCustomData()
	transportCfg := proxy.NewTransportConfig()
	wsStore := proxy.NewWSStore(10000)

	hub := api.NewHub()
	go hub.Run()

	// Load plugins from ~/.joro/plugins/.
	pluginMgr := plugins.NewManager(filepath.Join(cfg.DataDir, "plugins"), hub.Broadcast())
	if err := pluginMgr.Start(ctx); err != nil {
		log.Printf("plugin manager: %v", err)
	}
	defer pluginMgr.Shutdown()

	ctx, cancel := context.WithCancel(ctx)

	proxyHandler := proxy.NewHandler(certCache, store, interceptQ, scope, noise, replace, customData, transportCfg, wsStore, hub.Broadcast())
	if len(pluginMgr.ProxyHooks()) > 0 {
		proxyHandler.SetHookRunner(pluginMgr)
	}
	proxySrv := proxy.NewServer(cfg.BindAddr, cfg.ProxyPort, proxyHandler)
	apiSrv := api.New(cfg, store, interceptQ, scope, noise, replace, customData, transportCfg, wsStore, ca, hub, noteStore, pluginMgr, api.BuildInfo{
		Version:         version,
		Commit:          commit,
		UpdateAvailable: updateAvailable,
		LatestVersion:   latestVersion,
	}, cancel)

	// Periodically save the active project when auto-save is enabled.
	apiSrv.StartAutoSaveLoop(ctx)

	// Start proxy server.
	proxyDone := make(chan struct{})
	go func() {
		defer close(proxyDone)
		fmt.Printf("Proxy listening on %s:%d\n", cfg.BindAddr, cfg.ProxyPort)
		if err := proxySrv.Start(ctx); err != nil {
			log.Printf("proxy server: %v", err)
		}
	}()

	// Start API + UI server (blocks).
	// The proxy-mode UI/API always binds to loopback regardless of --bind.
	fmt.Printf("UI available at http://127.0.0.1:%d\n", cfg.UIPort)
	fmt.Printf("CA cert: %s/ca.crt  (import into browser/OS trust store)\n", cfg.DataDir)
	if err := apiSrv.Start(ctx); err != nil {
		log.Fatalf("API server: %v", err)
	}

	// If the API server was shut down for a restart (update), re-exec.
	if apiSrv.RestartRequested() {
		// Wait for proxy to finish shutting down so the port is free.
		<-proxyDone
		if err := update.Restart(); err != nil {
			log.Fatalf("Restart failed: %v", err)
		}
	}
}

// hostPluginBuildFlags returns build flags + env vars that must match the
// host binary so Go's plugin loader will accept the resulting .so/.dylib.
// Derived from runtime/debug.BuildInfo of the running binary. Without this,
// a host built with `-trimpath -tags netgo,osusergo` (release config) and a
// plugin built with bare `go build -buildmode=plugin` produce different
// stdlib package hashes, and dlopen rejects the plugin with
// "plugin was built with a different version of package internal/goarch".
func hostPluginBuildFlags() (flags []string, env []string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil, nil
	}
	var tags string
	for _, s := range info.Settings {
		switch s.Key {
		case "-trimpath":
			if s.Value == "true" {
				flags = append(flags, "-trimpath")
			}
		case "-tags":
			tags = s.Value
		case "CGO_ENABLED":
			env = append(env, "CGO_ENABLED="+s.Value)
		case "GOARM64":
			env = append(env, "GOARM64="+s.Value)
		case "GOAMD64":
			env = append(env, "GOAMD64="+s.Value)
		}
	}
	if tags != "" {
		flags = append(flags, "-tags", tags)
	}
	return flags, env
}

// runBuildPlugin compiles a Go plugin from srcDir. Returns an exit code.
func runBuildPlugin(srcDir, output string, install bool, dataDir string) int {
	// Go's plugin package and -buildmode=plugin are not supported on Windows.
	if runtime.GOOS == "windows" {
		fmt.Fprintln(os.Stderr, "error: plugins are not supported on Windows (Go's plugin package is Linux/macOS/FreeBSD only)")
		return 1
	}

	srcDir, err := filepath.Abs(srcDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	info, err := os.Stat(srcDir)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "error: %s is not a directory\n", srcDir)
		return 1
	}

	// Determine output filename.
	base := filepath.Base(srcDir)
	soName := base + ".so"
	if runtime.GOOS == "darwin" {
		soName = base + ".dylib"
	}

	outPath := filepath.Join(srcDir, soName)
	if output != "" {
		outPath, _ = filepath.Abs(output)
	}

	hostFlags, hostEnv := hostPluginBuildFlags()

	fmt.Printf("Building plugin from %s\n", srcDir)
	fmt.Printf("  Go version: %s\n", runtime.Version())
	fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  Output:     %s\n", outPath)
	if len(hostFlags) > 0 {
		fmt.Printf("  Flags:      %s\n", strings.Join(hostFlags, " "))
	}
	if len(hostEnv) > 0 {
		fmt.Printf("  Env:        %s\n", strings.Join(hostEnv, " "))
	}

	// Go's plugin loader rejects .so files built with a different Go toolchain
	// version than the host binary. Warn loudly when `go build` in srcDir
	// would use a different toolchain than this binary was compiled with.
	// Run `go version` from srcDir so the plugin's go.mod (and any
	// auto-toolchain directive) influences which version is reported.
	if v, ok := localGoVersion(srcDir); ok && v != runtime.Version() {
		fmt.Fprintf(os.Stderr, "  Warning: local Go toolchain (%s) differs from this binary's Go version (%s).\n", v, runtime.Version())
		fmt.Fprintf(os.Stderr, "           The built plugin may fail to load. Match versions or rebuild joro from source.\n")
	}

	// Run go build -buildmode=plugin, forwarding the host's ABI-relevant
	// flags + env (-trimpath, -tags, GOARM64, ...) so the plugin's stdlib
	// hashes match and dlopen accepts it.
	args := []string{"build", "-buildmode=plugin"}
	args = append(args, hostFlags...)
	args = append(args, "-o", outPath, ".")
	cmd := exec.Command("go", args...)
	cmd.Dir = srcDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if len(hostEnv) > 0 {
		cmd.Env = append(os.Environ(), hostEnv...)
	}
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n", err)
		return 1
	}

	fmt.Printf("  Build successful\n")

	// Optionally install to ~/.joro/plugins/.
	if install {
		pluginDir := filepath.Join(dataDir, "plugins")
		if err := os.MkdirAll(pluginDir, 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "error creating plugin dir: %v\n", err)
			return 1
		}

		destPath := filepath.Join(pluginDir, soName)
		src, err := os.Open(outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading built plugin: %v\n", err)
			return 1
		}
		defer src.Close()

		dst, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error writing to plugin dir: %v\n", err)
			return 1
		}
		defer dst.Close()

		if _, err := io.Copy(dst, src); err != nil {
			fmt.Fprintf(os.Stderr, "error copying plugin: %v\n", err)
			return 1
		}

		fmt.Printf("  Installed to %s\n", destPath)
		fmt.Println("  Restart Joro to load the plugin")
	}

	return 0
}

// localGoVersion returns the version reported by `go version` when run from
// dir (e.g. "go1.25.0"). Running in dir lets a project-local go.mod with a
// `go` directive trigger Go's auto-toolchain download, so the reported
// version matches what `go build` will actually use. Returns ok=false if
// `go` is missing or the output is unparseable.
func localGoVersion(dir string) (string, bool) {
	cmd := exec.Command("go", "version")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	fields := strings.Fields(string(out))
	if len(fields) < 3 {
		return "", false
	}
	return fields[2], true
}
