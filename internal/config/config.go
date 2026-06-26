package config

import (
	"os"
	"path/filepath"
)

// Config holds application-wide configuration.
type Config struct {
	BindAddr           string
	ProxyPort          int
	UIPort             int
	DataDir            string
	Dev                bool
	ViteURL            string
	Listener           bool
	CallbackDNSPort    int
	CallbackHTTPPort   int
	CallbackHTTPSPort  int
	CallbackSMTPPort   int
	CallbackSMTPSPort  int
	CallbackFTPPort    int
	CallbackFTPSPort   int
	CallbackLDAPPort   int
	CallbackLDAPSPort  int
	CallbackDomain      string
	CallbackResponseIP  string
	TLSCertFile         string
	TLSKeyFile          string
	TeamServer          bool
	DisableUpdateChecks bool
	AllowedHosts        []string
}

// Default returns a Config populated with sensible defaults.
func Default() Config {
	homeDir, _ := os.UserHomeDir()
	return Config{
		BindAddr:         "127.0.0.1",
		ProxyPort:        8080,
		UIPort:           9090,
		DataDir:          filepath.Join(homeDir, ".joro"),
		ViteURL:          "http://localhost:5173",
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
