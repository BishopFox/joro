// hello-dashboard is an example dashboard plugin that replaces the default
// Dashboard page with a custom engagement overview.
//
// Build:
//
//	go build -buildmode=plugin -o hello-dashboard.so .      # Linux
//	go build -buildmode=plugin -o hello-dashboard.dylib .   # macOS
//
// Then place the file in ~/.joro/plugins/ and restart Joro.
// The Dashboard tab will render this plugin's UI instead of the built-in page.
package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"time"

	"github.com/BishopFox/joro/sdk"
)

//go:embed ui
var uiFS embed.FS

// Plugin is the exported symbol that Joro looks up when loading the plugin.
var Plugin sdk.Plugin = &HelloDashboard{}

// HelloDashboard demonstrates replacing the built-in Dashboard with a custom UI.
type HelloDashboard struct {
	startTime time.Time
}

func (d *HelloDashboard) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "hello-dashboard",
		Version:     "1.0.0",
		Description: "Example Dashboard",
		Type:        sdk.TypeDashboard,
	}
}

func (d *HelloDashboard) Init(_ sdk.PluginContext) error {
	d.startTime = time.Now()
	return nil
}

func (d *HelloDashboard) Shutdown() error { return nil }

func (d *HelloDashboard) Routes() []sdk.Route {
	return []sdk.Route{
		{
			Method:  "GET",
			Pattern: "/stats",
			Handler: d.handleStats,
		},
	}
}

func (d *HelloDashboard) UIAssets() fs.FS {
	sub, _ := fs.Sub(uiFS, "ui")
	return sub
}

func (d *HelloDashboard) handleStats(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"uptime":    time.Since(d.startTime).Round(time.Second).String(),
		"startTime": d.startTime.Format(time.RFC3339),
	})
}
