// hello-tab is an example top-level tab extension for Joro.
//
// Build:
//
//	go build -buildmode=plugin -o hello-tab.so .
//
// Then place hello-tab.so in ~/.joro/plugins/ and restart Joro.
// A "Hello" tab will appear in the top-level navigation.
package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"

	"github.com/BishopFox/joro/sdk"
)

//go:embed ui
var uiFS embed.FS

// Plugin is the exported symbol that Joro looks up when loading the plugin.
var Plugin sdk.Plugin = &HelloTab{}

type HelloTab struct{}

func (t *HelloTab) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "hello-tab",
		Version:     "1.0.0",
		Description: "Hello Tab",
		Type:        sdk.TypeTab,
	}
}

func (t *HelloTab) Init(_ sdk.PluginContext) error { return nil }
func (t *HelloTab) Shutdown() error                   { return nil }

func (t *HelloTab) TabInfo() sdk.TabMeta {
	return sdk.TabMeta{Label: "Hello"}
}

func (t *HelloTab) Routes() []sdk.Route {
	return []sdk.Route{
		{
			Method:  "GET",
			Pattern: "/hello",
			Handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"message": "Hello from the tab extension!"}) //nolint:errcheck
			},
		},
	}
}

func (t *HelloTab) UIAssets() fs.FS {
	sub, _ := fs.Sub(uiFS, "ui")
	return sub
}
