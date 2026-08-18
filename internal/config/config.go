package config

import (
	"os"
	"path/filepath"
)

// Config holds application-wide configuration.
type Config struct {
	BindAddr            string
	ProxyPort           int
	UIPort              int
	DataDir             string
	Dev                 bool
	ViteURL             string
	Listener            bool
	CallbackDNSPort     int
	CallbackHTTPPort    int
	CallbackHTTPSPort   int
	CallbackSMTPPort    int
	CallbackSMTPSPort   int
	CallbackFTPPort     int
	CallbackFTPSPort    int
	CallbackLDAPPort    int
	CallbackLDAPSPort   int
	CallbackDomain      string
	CallbackResponseIP  string
	TLSCertFile         string
	TLSKeyFile          string
	TeamServer          bool
	DisableUpdateChecks bool
	AllowedHosts        []string
	// NoAutomation disables the capability registry, the automation token store
	// and the MCP listener entirely: no routes registered, no second port bound,
	// no token file read. A deployment-posture switch, in the same family as
	// --allowed-host and --disable-update-checks, not a way to invoke a feature.
	NoAutomation bool
	// AutomationPrivileged registers the execution and C2 capabilities. Off by
	// default; even when on, no token profile grants one, so the operator must select
	// each by hand. A launch flag rather than a Settings toggle so enabling it cannot
	// happen without a restart.
	AutomationPrivileged bool
	// AutomationScripting registers script.run, which executes submitted JavaScript in
	// a sandboxed worker process against a fixed SDK bundle. Its own flag rather than
	// riding on AutomationPrivileged, which means web shell and C2 specifically: an
	// operator should be able to allow scripting without allowing command execution,
	// or the reverse. Same posture otherwise — off by default, no profile grants it,
	// and a restart is required to change it.
	AutomationScripting bool
}

// Default returns a Config populated with sensible defaults.
func Default() Config {
	homeDir, _ := os.UserHomeDir()
	return Config{
		BindAddr:          "127.0.0.1",
		ProxyPort:         8080,
		UIPort:            9090,
		DataDir:           filepath.Join(homeDir, ".joro"),
		ViteURL:           "http://localhost:5173",
		CallbackDNSPort:   53,
		CallbackHTTPPort:  80,
		CallbackHTTPSPort: 443,
		CallbackSMTPPort:  25,
		CallbackSMTPSPort: 465,
		CallbackFTPPort:   21,
		CallbackLDAPPort:  389,
		// FTPS (990) and LDAPS (636) default to 0 (disabled).
	}
}
