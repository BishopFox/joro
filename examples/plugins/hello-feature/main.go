// hello-feature is an example plugin feature (sub-tab in the Plugins page).
//
// Build:
//
//	go build -buildmode=plugin -o hello-feature.so .
//
// Then place hello-feature.so in ~/.joro/plugins/ and restart Joro.
// A "Hello Feature" sub-tab will appear in the Plugins page.
package main

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/BishopFox/joro/sdk"
)

//go:embed ui
var uiFS embed.FS

// Plugin is the exported symbol that Joro looks up when loading the plugin.
var Plugin sdk.Plugin = &HelloFeature{}

type HelloFeature struct{}

func (f *HelloFeature) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "hello-feature",
		Version:     "1.0.0",
		Description: "Hello Feature",
		Type:        sdk.TypeFeature,
	}
}

func (f *HelloFeature) Init(_ sdk.PluginContext) error { return nil }
func (f *HelloFeature) Shutdown() error                   { return nil }

func (f *HelloFeature) TabInfo() sdk.TabMeta {
	return sdk.TabMeta{Label: "Hello Feature"}
}

func (f *HelloFeature) Routes() []sdk.Route {
	return []sdk.Route{
		{
			Method:  "GET",
			Pattern: "/ping",
			Handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(`{"pong": true}`)) //nolint:errcheck
			},
		},
	}
}

func (f *HelloFeature) UIAssets() fs.FS {
	sub, _ := fs.Sub(uiFS, "ui")
	return sub
}
