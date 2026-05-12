// hello-provider is an example execution provider extension for Joro.
//
// Build:
//
//	go build -buildmode=plugin -o hello-provider.so .
//
// Then place hello-provider.so in ~/.joro/plugins/ and restart Joro.
// A "Hello Provider" mode will appear in the Execute tab.
package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/BishopFox/joro/sdk"
)

// Plugin is the exported symbol that Joro looks up when loading the plugin.
var Plugin sdk.Plugin = &HelloProvider{}

type HelloProvider struct {
	connected bool
	greeting  string
}

func (h *HelloProvider) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "hello-provider",
		Version:     "1.0.0",
		Description: "Hello Provider",
		Type:        sdk.TypeExecProvider,
	}
}

func (h *HelloProvider) Init(_ sdk.PluginContext) error { return nil }
func (h *HelloProvider) Shutdown() error                   { return nil }

func (h *HelloProvider) ConfigSchema() []sdk.ConfigField {
	return []sdk.ConfigField{
		{
			Name:        "greeting",
			Label:       "Greeting",
			Type:        "text",
			Placeholder: "Hello",
			Required:    false,
			HelpText:    "The greeting to use in responses",
		},
	}
}

func (h *HelloProvider) Connect(_ context.Context, config map[string]string) error {
	h.greeting = config["greeting"]
	if h.greeting == "" {
		h.greeting = "Hello"
	}
	h.connected = true
	return nil
}

func (h *HelloProvider) Disconnect(_ context.Context) error {
	h.connected = false
	return nil
}

func (h *HelloProvider) IsConnected() bool {
	return h.connected
}

func (h *HelloProvider) Status(_ context.Context) sdk.ProviderStatus {
	return sdk.ProviderStatus{
		Connected: h.connected,
		DisplayInfo: map[string]string{
			"greeting": h.greeting,
		},
	}
}

func (h *HelloProvider) Command(_ context.Context, input string) sdk.CommandResult {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return sdk.CommandResult{Error: "empty command"}
	}

	switch strings.ToLower(parts[0]) {
	case "help":
		return sdk.CommandResult{Output: "Available commands: help, greet <name>, clear"}
	case "greet":
		name := "World"
		if len(parts) > 1 {
			name = strings.Join(parts[1:], " ")
		}
		return sdk.CommandResult{Output: fmt.Sprintf("%s, %s!", h.greeting, name)}
	case "clear":
		return sdk.CommandResult{Clear: true}
	default:
		return sdk.CommandResult{Error: fmt.Sprintf("unknown command: %s", parts[0])}
	}
}

func (h *HelloProvider) PromptPrefix() string {
	return "hello > "
}

// GraphProvider implementation — shows example nodes on the Dashboard.

func (h *HelloProvider) GraphData(_ context.Context) sdk.GraphInfo {
	if !h.connected {
		return sdk.GraphInfo{}
	}
	return sdk.GraphInfo{
		Server: &sdk.GraphServer{
			Label: "Hello Server",
			Host:  "127.0.0.1",
			Port:  1234,
		},
		Nodes: []sdk.GraphNode{
			{
				ID:            "example-agent-1",
				Name:          "AGENT-01",
				Hostname:      "example-host",
				OS:            "linux",
				Arch:          "amd64",
				RemoteAddress: "192.168.1.100:49221",
				Transport:     "https",
				Username:      "root",
				Type:          "agent",
				Status:        "active",
			},
		},
	}
}
