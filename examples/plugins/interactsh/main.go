// Interactsh example plugin — an InteractProvider that polls remote interactsh
// servers for OOB interactions. Stdlib-only: no projectdiscovery dependency,
// no third-party modules beyond the Joro SDK. See wire.go for the
// reimplemented interactsh wire protocol.
//
// Build:
//
//	./joro --build-plugin examples/plugins/interactsh --install
//
// A new "Interactsh" input group appears in the Interact tab after restart.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/joro/sdk"
)

var Plugin sdk.Plugin = &provider{store: newStore()}

type provider struct {
	mu        sync.Mutex
	store     *store
	rootCtx   context.Context
	rootStop  context.CancelFunc
	broadcast chan<- sdk.Event
}

func (p *provider) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "interactsh",
		Version:     "1.0.0",
		Description: "Interactsh",
		Type:        sdk.TypeInteractProvider,
	}
}

func (p *provider) Init(ctx sdk.PluginContext) error {
	p.broadcast = ctx.Broadcast
	p.rootCtx, p.rootStop = context.WithCancel(context.Background())
	return nil
}

func (p *provider) Shutdown() error {
	// Best-effort deregister for every active server, then cancel root ctx.
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range p.store.listServers() {
		if srv.cancel != nil {
			srv.cancel()
		}
		if srv.correlationID != "" {
			deregisterServer(shutCtx, srv)
		}
	}
	if p.rootStop != nil {
		p.rootStop()
	}
	return nil
}

func (p *provider) Info() sdk.InteractInfo {
	return sdk.InteractInfo{
		Label:       "Interactsh",
		ButtonLabel: "Add Interactsh",
		HelpText:    "Poll a remote interactsh server for OOB interactions",
	}
}

func (p *provider) ConfigSchema() []sdk.ConfigField {
	return []sdk.ConfigField{
		{Name: "serverUrl", Label: "Server URL", Type: "text", Placeholder: "https://oast.live", Required: true},
		{Name: "authToken", Label: "Auth token", Type: "password"},
		{Name: "insecureSkipVerify", Label: "Skip TLS verify", Type: "checkbox", HelpText: "Accept self-signed certs on self-hosted servers"},
	}
}

func (p *provider) CreateInstance(ctx context.Context, config map[string]string) (sdk.InteractInstance, error) {
	serverURL := strings.TrimSpace(config["serverUrl"])
	if serverURL == "" {
		return sdk.InteractInstance{}, fmt.Errorf("serverUrl is required")
	}
	if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		serverURL = "https://" + serverURL
	}

	srv := &server{
		id:         generateID(16),
		serverURL:  serverURL,
		authToken:  strings.TrimSpace(config["authToken"]),
		skipVerify: config["insecureSkipVerify"] == "true",
		enabled:    true,
		createdAt:  time.Now(),
		status:     "connecting",
	}

	// Register synchronously so the user sees the failure in the UI immediately
	// if the server is unreachable / rejects the token.
	registerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := registerServer(registerCtx, srv); err != nil {
		srv.status = "error"
		srv.errMsg = err.Error()
		return sdk.InteractInstance{}, err
	}
	srv.status = "connected"
	p.store.addServer(srv)
	p.startPoll(srv)
	return toInstance(srv), nil
}

func (p *provider) ListInstances(ctx context.Context) ([]sdk.InteractInstance, error) {
	servers := p.store.listServers()
	out := make([]sdk.InteractInstance, 0, len(servers))
	for _, srv := range servers {
		out = append(out, toInstance(srv))
	}
	return out, nil
}

func (p *provider) DeleteInstance(ctx context.Context, id string) error {
	srv := p.store.removeServer(id)
	if srv == nil {
		return fmt.Errorf("instance %s not found", id)
	}
	if srv.cancel != nil {
		srv.cancel()
	}
	if srv.correlationID != "" {
		deregisterServer(ctx, srv)
	}
	p.store.clearInteractions(id)
	return nil
}

func (p *provider) SetInstanceEnabled(ctx context.Context, id string, enabled bool) error {
	srv := p.store.getServer(id)
	if srv == nil {
		return fmt.Errorf("instance %s not found", id)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if srv.enabled == enabled {
		return nil
	}
	srv.enabled = enabled
	if enabled {
		srv.status = "connecting"
		p.startPoll(srv)
	} else {
		if srv.cancel != nil {
			srv.cancel()
			srv.cancel = nil
		}
		srv.status = "disabled"
	}
	return nil
}

func (p *provider) ListInteractions(ctx context.Context, instanceID string, offset, limit int) (sdk.InteractionPage, error) {
	items, total := p.store.listInteractions(instanceID, offset, limit)
	out := make([]sdk.InteractInteraction, len(items))
	for i, ix := range items {
		out[i] = sdk.InteractInteraction{
			ID:         ix.ID,
			InstanceID: ix.ServerID,
			Hex:        ix.UniqueID,
			Protocol:   ix.Protocol,
			SourceIP:   ix.SourceIP,
			Timestamp:  ix.Timestamp,
			QueryName:  ix.FullID,
			QueryType:  ix.QType,
			Method:     ix.Method,
			Path:       ix.Path,
			RawRequest: ix.RawRequest,
		}
	}
	return sdk.InteractionPage{Items: out, Total: total, Offset: offset, Limit: limit}, nil
}

func (p *provider) ClearInteractions(ctx context.Context, instanceID string) error {
	p.store.clearInteractions(instanceID)
	return nil
}

// startPoll launches the poll loop for srv under a child context of p.rootCtx.
// Caller must hold p.mu when calling from SetInstanceEnabled. CreateInstance
// is sequential per-call so mu isn't required.
func (p *provider) startPoll(srv *server) {
	pollCtx, cancel := context.WithCancel(p.rootCtx)
	srv.cancel = cancel
	go pollLoop(pollCtx, srv,
		func(ix *serverInteraction) { p.handleInteraction(srv, ix) },
		func(status, errMsg string) {
			srv.status = status
			srv.errMsg = errMsg
		},
	)
}

// handleInteraction maps a raw server.Interaction to our storage/event shape
// and broadcasts it so the UI merges it into the unified event feed.
func (p *provider) handleInteraction(srv *server, ix *serverInteraction) {
	proto := strings.ToLower(ix.Protocol)
	method, path := "", ""
	if proto == "http" && ix.RawRequest != "" {
		if line, _, ok := strings.Cut(ix.RawRequest, "\r\n"); ok {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) >= 2 {
				method, path = parts[0], parts[1]
			}
		}
	}
	raw := ""
	if ix.RawRequest != "" {
		raw = base64.StdEncoding.EncodeToString([]byte(ix.RawRequest))
	}
	stored := storedInteraction{
		ID:         randHex(16),
		ServerID:   srv.id,
		Protocol:   proto,
		UniqueID:   ix.UniqueID,
		FullID:     ix.FullID,
		QType:      ix.QType,
		Method:     method,
		Path:       path,
		SourceIP:   ix.RemoteAddress,
		Timestamp:  ix.Timestamp,
		RawRequest: raw,
	}
	p.store.recordInteraction(stored)

	if p.broadcast != nil {
		select {
		case p.broadcast <- sdk.Event{
			Type: "interaction",
			Data: sdk.InteractInteraction{
				ID:         stored.ID,
				InstanceID: stored.ServerID,
				Hex:        stored.UniqueID,
				Protocol:   stored.Protocol,
				SourceIP:   stored.SourceIP,
				Timestamp:  stored.Timestamp,
				QueryName:  stored.FullID,
				QueryType:  stored.QType,
				Method:     stored.Method,
				Path:       stored.Path,
				RawRequest: stored.RawRequest,
			},
		}:
		default:
		}
	}
}

// toInstance projects a server into the SDK-facing InteractInstance view.
func toInstance(srv *server) sdk.InteractInstance {
	status := srv.status
	if !srv.enabled {
		status = "disabled"
	}
	payloadURL := ""
	if srv.correlationID != "" && srv.payloadHost != "" {
		payloadURL = fmt.Sprintf("%s%s.%s", srv.correlationID, srv.nonce, srv.payloadHost)
	}
	meta := map[string]string{}
	if srv.errMsg != "" {
		meta["error"] = srv.errMsg
	}
	return sdk.InteractInstance{
		ID:         srv.id,
		Label:      srv.serverURL,
		Hex:        srv.correlationID,
		Status:     status,
		Enabled:    srv.enabled,
		PayloadURL: payloadURL,
		Meta:       meta,
	}
}

// randHex returns a random hex string of length 2*n, for interaction record IDs.
func randHex(n int) string {
	raw := make([]byte, n)
	for i := 0; i < n; i++ {
		raw[i] = byte(time.Now().UnixNano() >> uint(i*3))
	}
	// XOR with fresh randomness so IDs are unique even within the same nanosecond tick.
	fresh := []byte(generateID(n))
	for i := 0; i < n; i++ {
		raw[i] ^= fresh[i]
	}
	return hex.EncodeToString(raw)
}
