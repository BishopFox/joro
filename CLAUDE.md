# Joro - Claude Code Instructions

## Keeping This File Fresh

**Update this file whenever significant changes are made to the project** - new packages, changed commands, architectural decisions, or new conventions. Outdated instructions cause mistakes. If you add a dependency, change a build step, or restructure a package, update the relevant section here before finishing the task.

---

## Project Overview

Joro is an intercepting HTTP/HTTPS proxy and web shell toolkit for penetration testing. It is a single Go binary that starts a proxy server and serves a React web UI - there is no CLI mode.

Joro has three modes:
- **Proxy mode** (default): intercepting proxy + web UI
- **Listener mode** (`--listener`): out-of-band callback server (DNS + HTTP) for blind vulnerability detection
- **Team Server mode** (`--listener --teamserver`): listener + authenticated team collaboration (shared chat, notes)

- **Proxy port:** 8080 (configurable via `--proxy-port`)
- **UI/API port:** 9090 (configurable via `--ui-port`)
- **Data dir:** `~/.joro/` - CA cert/key + callbacks.db stored here
- **Listener DNS port:** 53 (configurable via `--dns-port`)
- **Listener HTTP port:** 80 (configurable via `--http-port`)
- **Listener HTTPS port:** 443 (configurable via `--https-port`, set to `0` to disable)
- **Listener domain:** set via `--domain` flag or UI config

---

## Repository Structure

```
main.go                      - Entrypoint: proxy or listener mode
internal/
  config/config.go           - Config struct and defaults
  event/
    event.go                 - Shared WSEvent struct (used by proxy + callback)
  callback/
    db.go                    - SQLite setup (modernc.org/sqlite, no CGO)
    store.go                 - Token + Interaction CRUD
    token.go                 - Token generation (12-hex-char) + correlation
    dns.go                   - DNS callback listener (miekg/dns)
    http.go                  - HTTP callback listener
  cert/
    ca.go                    - ECDSA P-256 CA generation and loading
    leaf.go                  - Per-host leaf cert generation
    cache.go                 - sync.Map cert cache
  proxy/
    proxy.go                 - HTTP proxy server lifecycle
    handler.go               - ServeHTTP: routes CONNECT vs plain HTTP
    mitm.go                  - TLS termination and HTTP/1.1 loop
    intercept.go             - Per-request intercept queue with timeouts
    noise.go                 - Noise filter: silently tunnels browser background traffic
    scope.go                 - Two-level scope filtering (host + method/path)
    store.go                 - Thread-safe ring buffer of captured requests
    replace.go               - Match & Replace rules (CRUD + Apply logic)
    customdata.go            - Custom Data injection (additive headers/query/body)
    websocket.go             - WebSocket frame reader/writer + isWebSocketUpgrade
    ws_relay.go              - WebSocket relay loop + upgrade handlers (HTTP + MITM)
    ws_store.go              - Ring buffer for captured WebSocket messages
    ws_manipulate.go         - User-driven outbound WS sessions (dial, send, close)
    client.go                - NewHTTPClient, MakeRequest
    helpers.go               - Shared utilities (ID gen, dump, events)
  team/
    db.go                    - Team tables migration (team_chat, team_notes)
    store.go                 - Team chat + notes CRUD
    auth.go                  - Bearer token auth middleware + nickname context
  fuzzer/
    fuzzer.go                - Campaign, Result, Config types + Run() goroutine pool
    store.go                 - In-memory campaign store (max 50)
  shell/
    generate.go              - ASP/ASPX/PHP web shell generation
    execute.go               - ExecuteCommand (sends cmd to deployed shell)
    dictionary.go            - Random variable name generator
  sliver/
    client.go                - gRPC client to Sliver teamserver (mTLS, all RPCs)
    config.go                - OperatorConfig struct
    wire.go                  - Custom protobuf wire encoding/decoding (protowire)
    commands.go              - Command dispatcher: parses input, routes to RPC, formats output
  plugins/
    manager.go               - Plugin lifecycle: load, categorize, init, shutdown
    loader.go                - Scan dir, open .so/.dylib, lookup Plugin symbol, validate
  api/
    server.go                - APIServer struct, Start(), SPA embedding
    routes.go                - All route registrations
    ws.go                    - WebSocket hub (gorilla/websocket)
    handlers_requests.go     - GET/DELETE /api/v1/requests
    handlers_intercept.go    - Intercept queue endpoints
    handlers_manipulate.go   - POST /api/v1/manipulate/send
    handlers_manipulate_ws.go - WS Manipulate: connect/send/disconnect endpoints
    handlers_noise.go        - Noise filter CRUD endpoints
    handlers_scope.go        - Scope CRUD endpoints
    handlers_generate.go     - POST /api/v1/generate
    handlers_execute.go      - POST /api/v1/execute
    handlers_fuzzer.go       - Fuzzer campaign endpoints (start/stop/list/results/wordlist)
    handlers_settings.go     - GET/PUT /api/v1/settings
    handlers_certs.go        - GET /api/v1/certs/ca.crt
    handlers_callbacks.go    - Callback token/interaction/config endpoints
    handlers_replace.go      - Match & Replace CRUD endpoints
    handlers_customdata.go   - Custom Data CRUD endpoints
    handlers_plugins.go      - Plugin management + dynamic per-plugin route registration
    handlers_interact_plugins.go - InteractProvider plugin endpoints (list/CRUD instances + interactions)
    handlers_team.go         - Team chat/notes/users endpoints + proxy forwarding
    ws_relay.go              - WebSocket relay: connects to teamserver, forwards team.* events
    handlers_ws.go           - WebSocket message list/clear endpoints
    handlers_sliver.go       - Sliver C2: connect/disconnect/command/download/upload
sdk/
  sdk.go                     - Plugin SDK: interfaces, types, constants (separate Go module)
web/
  embed.go                   - //go:embed dist (package web)
  dist/                      - Built frontend (gitignored except placeholder)
  src/
    main.tsx                 - React entry point
    App.tsx                  - Router + nav tabs
    index.css                - Tailwind base styles + theme imports
    vite-env.d.ts            - Vite client type declarations
    themes/
      bishop-fox.css       - Default dark theme CSS custom properties (BF brand palette)
    lib/
      api.ts                 - Typed fetch wrapper for all API endpoints
      ws.ts                  - WebSocket singleton with auto-reconnect
    stores/
      requestStore.ts        - Zustand: HTTP history
      fuzzStore.ts            - Zustand: fuzzer campaigns, results, config
      interceptStore.ts      - Zustand: intercept queue + enabled state
      settingsStore.ts       - Zustand: app settings
      callbackStore.ts       - Zustand: callback tokens, interactions, config
      wsStore.ts             - Zustand: WebSocket messages
      manipulateWSStore.ts   - Zustand: WS Manipulate tabs (upgrade, session, frames)
      teamStore.ts           - Zustand: team chat messages + active users
    pages/
      History.tsx            - HTTP/WebSocket sub-tabs, request table + WS message viewer
      Intercept.tsx          - Intercept queue + CodeMirror editor
      Manipulate.tsx         - HTTP/WebSocket sub-tab switcher
      ManipulateHTTP.tsx     - Raw HTTP request editor + response viewer
      ManipulateWS.tsx       - Raw WS upgrade editor + live frame transcript + send editor
      Generator.tsx          - Generate page - web shell generation UI
      Executor.tsx           - Execute page - command execution terminal UI
      Fuzz.tsx               - Fuzz page - request fuzzer with FUZZ keyword substitution
      Login.tsx              - Team server auth form (nickname + token)
      Settings.tsx           - Settings form + CA cert download + team server config
      Callbacks.tsx          - Callback tokens + interactions + detail panel
      Plugins.tsx            - Plugin management: upload, delete, restart
      PluginTabPage.tsx       - Iframe wrapper for tab-type plugin UIs
    components/
      DynamicConfigForm.tsx   - Auto-generated config form for plugin ExecProviders
examples/
  plugins/
    hello-provider/          - Example ExecProvider + GraphProvider plugin
    hello-tab/               - Example top-level tab plugin with embedded UI
    hello-feature/           - Example feature sub-tab plugin with embedded UI
    hello-dashboard/         - Example dashboard replacement plugin
    interactsh/              - InteractProvider: stdlib-only interactsh client (RSA-OAEP + AES-CTR)
Makefile                     - build, build-frontend, build-all, dev, clean
```

---

## Build Commands

```bash
# Go-only build (uses placeholder frontend, works without npm)
go build ./...

# Full build (frontend + Go binary)
make build

# Cross-platform binaries → dist/
make build-all

# Development: backend proxies UI to Vite dev server
make dev                     # runs: go run . --dev
cd web && npm run dev        # run in a separate terminal

# Build a plugin from source (detects .so vs .dylib by OS)
./joro --build-plugin examples/plugins/hello-feature
./joro --build-plugin examples/plugins/hello-feature --install  # also copies to ~/.joro/plugins/

# Or build manually:
cd examples/plugins/hello-feature
go build -buildmode=plugin -o hello-feature.dylib .   # macOS
go build -buildmode=plugin -o hello-feature.so .      # Linux
```

### Releases

Tagged release builds use [goreleaser](https://goreleaser.com) — config lives at `.goreleaser.yaml` in the repo root. `make build` / `make build-all` remain the local-dev workflow; goreleaser is only for cutting releases.

```bash
# Local snapshot build (no tag, no upload) — sanity check the config
goreleaser release --snapshot --clean

# Verify config syntax
goreleaser check

# Cut a real release (requires GITHUB_TOKEN with repo scope, and a pushed tag)
git tag v1.0.1 && git push --tags
goreleaser release --clean
```

The release matrix is broader than `make build-all` — goreleaser produces 6 binaries (linux/{amd64,arm64}, darwin/{amd64,arm64}, windows/{amd64,arm64}) while `make build-all` stays at the original 3 (linux/amd64, darwin/arm64, windows/amd64) for fast local cross-compile. Goreleaser produces tar.gz/zip archives with the binary, LICENSE, and README, plus a `checksums.txt` covering all archives. Releases are created as **drafts** so the operator reviews and publishes manually.

`-X main.version={{.Tag}}` and `-X main.commit={{.ShortCommit}}` are injected at link time. Plain `go build ./...` still produces a binary that reports the source-default `v1.0.0 (dev)`.

The asset name template (`joro_<version>_<os>_<arch>.tar.gz|zip`) is duplicated in `internal/update/update.go` (`runBinaryUpdate`) — keep them in sync.

### In-app updater install modes

`internal/update/update.go` detects how the running binary was installed and dispatches `CheckForUpdate` / `RunUpdate` accordingly:

- **Git mode** (`.git` dir alongside the executable): `git fetch` + parse upstream `main.go` version literal; update via `git pull --ff-only` + `make build`. This is what users who `git clone`d get.
- **Binary mode** (no `.git`): hits `GET /repos/BishopFox/joro/releases/latest` for the tag, downloads the matching goreleaser archive + `checksums.txt`, verifies SHA-256, atomically replaces the running binary. This is what users who downloaded a release archive get.

Both paths fail silently on any error (no network, GitHub rate limit, missing `git`, mismatched checksum) — startup is never blocked by an update-check failure. After a successful update, `update.Restart()` re-execs the binary.

---

## Frontend Development

The frontend lives in `web/`. Source is TypeScript/React/Vite.

```bash
cd web
npm install       # install dependencies
npm run dev       # Vite dev server on :5173 (use with `make dev`)
npm run build     # output to web/dist/ (embedded into Go binary)
```

**npm registry:** The machine's npm may be pointed at a private registry. If `npm install` fails, check with `npm config get registry` and reset with `npm config delete registry`.

---

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/requests` | Paginated history (`?offset=&limit=&host=&method=&status=&search=&exclude=`) |
| GET | `/api/v1/requests/:id` | Full request+response detail (raw bytes as base64) |
| DELETE | `/api/v1/requests` | Clear all history |
| GET | `/api/v1/intercept` | Current queue + enabled state |
| PUT | `/api/v1/intercept/enabled` | Toggle intercept `{"enabled": bool}` |
| POST | `/api/v1/intercept/:id/forward` | Forward (optionally with modified `reqRaw` base64) |
| POST | `/api/v1/intercept/:id/drop` | Drop intercepted request |
| POST | `/api/v1/manipulate/send` | Send raw HTTP request `{"raw": b64, "scheme": "", "host": ""}` |
| POST | `/api/v1/manipulate/ws/connect` | Open a user-driven WS session with a raw upgrade request `{"raw": b64, "scheme": "ws|wss", "host": ""}` → `{sessionId, status, rawResp, error}` (always HTTP 200; `sessionId` empty on failure) |
| POST | `/api/v1/manipulate/ws/{id}/send` | Send a frame on an open session `{"opcode": "text|binary|ping|pong|close", "payload": b64}` |
| POST | `/api/v1/manipulate/ws/{id}/disconnect` | Close a WS Manipulate session |
| POST | `/api/v1/generate` | Generate web shell `{"format": "php|asp|aspx|ashx|jsp|cfm"}` |
| POST | `/api/v1/execute` | Execute command `{"target","webshell","authKey","command"}` |
| POST | `/api/v1/fuzzer/start` | Start fuzz campaign `{raw, scheme, host, wordlist[], wordlists?, attackMode?, threads, rateLimit, followRedirects, updateContentLength?, matchers, filters}` |
| POST | `/api/v1/fuzzer/{id}/stop` | Stop running fuzz campaign |
| GET | `/api/v1/fuzzer/campaigns` | List all fuzz campaigns |
| GET | `/api/v1/fuzzer/campaigns/{id}` | Get campaign detail + paginated results `?offset=&limit=` |
| DELETE | `/api/v1/fuzzer/campaigns/{id}` | Delete completed fuzz campaign |
| POST | `/api/v1/fuzzer/wordlist` | Upload wordlist file (multipart) → `{lines[], count}` |
| GET | `/api/v1/noise` | Get noise filter state `{enabled, patterns}` |
| PUT | `/api/v1/noise/enabled` | Toggle noise filter `{"enabled": bool}` |
| POST | `/api/v1/noise/patterns` | Add noise pattern `{"pattern": "host.com"}` |
| DELETE | `/api/v1/noise/patterns/{id}` | Delete noise pattern by ID |
| GET | `/api/v1/scope` | Get scope state `{enabled, rules}` |
| PUT | `/api/v1/scope/enabled` | Toggle scope `{"enabled": bool}` |
| POST | `/api/v1/scope/rules` | Add scope rule `{pattern, methods, path, include}` |
| DELETE | `/api/v1/scope/rules/{id}` | Delete scope rule by ID |
| GET | `/api/v1/settings` | Get current settings |
| PUT | `/api/v1/settings` | Update settings `{"interceptEnabled", "interceptTimeout"}` |
| GET | `/api/v1/replace` | Get match/replace state + all rules |
| PUT | `/api/v1/replace/enabled` | Toggle match/replace `{"enabled": bool}` |
| POST | `/api/v1/replace/rules` | Add rule `{target, matchType, match, replace}` |
| DELETE | `/api/v1/replace/rules/{id}` | Delete rule by ID |
| GET | `/api/v1/customdata` | Get custom data state + all items |
| PUT | `/api/v1/customdata/enabled` | Toggle custom data `{"enabled": bool}` |
| POST | `/api/v1/customdata/items` | Add item `{type, name, value}` |
| DELETE | `/api/v1/customdata/items/{id}` | Delete item by ID |
| GET | `/api/v1/ws/messages` | List captured WS messages `?host=&offset=&limit=` |
| DELETE | `/api/v1/ws/messages` | Clear captured WS messages |
| GET | `/api/v1/certs/ca.crt` | Download CA certificate |
| GET | `/api/v1/mode` | Returns `{mode: "proxy"\|"listener"}` |
| GET | `/api/v1/callbacks/config` | Get callback config (domain, responseIp) |
| PUT | `/api/v1/callbacks/config` | Update callback config `{domain, responseIp}` |
| GET | `/api/v1/callbacks/tokens` | List all tokens with hit counts |
| POST | `/api/v1/callbacks/tokens` | Create token `{name}` → returns token with hex |
| DELETE | `/api/v1/callbacks/tokens/{id}` | Delete token + cascade interactions |
| GET | `/api/v1/callbacks/interactions` | List interactions `?token_id=&offset=&limit=` |
| DELETE | `/api/v1/callbacks/interactions` | Clear interactions `?token_id=` |
| WS | `/ws` | WebSocket event stream |
| GET | `/api/v1/sliver/status` | Sliver connection status + active session |
| POST | `/api/v1/sliver/connect` | Connect to Sliver teamserver `{operator config JSON}` |
| POST | `/api/v1/sliver/disconnect` | Disconnect from Sliver teamserver |
| GET | `/api/v1/sliver/sessions` | List sessions + beacons |
| POST | `/api/v1/sliver/execute` | Execute OS command `{sessionId, command, args}` |
| POST | `/api/v1/sliver/command` | Dispatch sliver-client command `{input}` → `{output, error, downloadId?, filename?}` |
| GET | `/api/v1/sliver/download/{id}` | Download cached binary (file download, screenshot, procdump) |
| POST | `/api/v1/sliver/upload` | Upload file to target (multipart: file + remotePath) |
| GET | `/api/v1/team/chat` | List team chat messages `?offset=&limit=` (teamserver) |
| POST | `/api/v1/team/chat` | Send chat message `{text}` (teamserver, auth required) |
| GET | `/api/v1/team/users` | List active connected users (teamserver) |
| POST | `/api/v1/team/nickname` | Rename caller's nickname in-place `{oldNickname, newNickname}` (teamserver, auth required) |
| GET | `/api/v1/team/notes/hosts` | List hosts with shared team notes (teamserver) |
| GET | `/api/v1/team/notes` | List team notes `?host=&offset=&limit=` (teamserver) |
| POST | `/api/v1/team/notes` | Create team note `{host, content}` (teamserver) |
| DELETE | `/api/v1/team/notes/{id}` | Delete team note (teamserver) |
| POST | `/api/v1/system/restart` | Graceful restart (re-exec binary with same args) |
| GET | `/api/v1/plugins` | List all loaded plugins with status |
| POST | `/api/v1/plugins/upload` | Upload plugin .so/.dylib (multipart, 32MB max) |
| DELETE | `/api/v1/plugins/{filename}` | Delete plugin file (restart required) |
| GET | `/api/v1/plugins/exec-providers` | List exec providers with config schemas |
| GET | `/api/v1/plugins/interact-providers` | List interact providers with `{info, configSchema}` |
| GET | `/api/v1/plugins/graph` | Aggregate graph data from connected GraphProviders |
| GET | `/api/v1/plugin/{name}/status` | Exec provider connection status |
| POST | `/api/v1/plugin/{name}/connect` | Connect exec provider `{config map}` |
| POST | `/api/v1/plugin/{name}/disconnect` | Disconnect exec provider |
| POST | `/api/v1/plugin/{name}/command` | Execute command via exec provider `{input}` |
| GET | `/api/v1/plugin/{name}/interact/instances` | List interact provider instances |
| POST | `/api/v1/plugin/{name}/interact/instances` | Create interact instance `{config map}` |
| DELETE | `/api/v1/plugin/{name}/interact/instances/{id}` | Delete interact instance |
| PUT | `/api/v1/plugin/{name}/interact/instances/{id}/enabled` | Toggle instance `{enabled}` |
| GET | `/api/v1/plugin/{name}/interact/interactions` | List interactions `?instance_id=&offset=&limit=` |
| DELETE | `/api/v1/plugin/{name}/interact/interactions` | Clear interactions `?instance_id=` |

### WebSocket Events

```json
{ "type": "request.captured", "data": { ...RequestSummary } }
{ "type": "intercept.queued",  "data": { "id", "method", "url", "host", "reqRaw" } }
{ "type": "intercept.resolved","data": { "id", "action": "forward|drop" } }
{ "type": "callback.interaction", "data": { ...Interaction } }
{ "type": "ws.message", "data": { "id", "connectionId", "timestamp", "direction", "opcode", "payloadLength", "payload", "host", "url", "isText" } }
{ "type": "team.chat", "data": { "id", "author", "text", "createdAt" } }
{ "type": "team.note", "data": { "id", "host", "content", "author", "createdAt", "updatedAt" } }
{ "type": "team.presence", "data": { "users": ["alice", "bob"] } }
{ "type": "team.nickname_changed", "data": { "oldNickname": "alice", "newNickname": "alice2" } }
{ "type": "fuzzer.started", "data": { "campaignId", "total" } }
{ "type": "fuzzer.result", "data": { "campaignId", "result": { "index", "payload", "payloads?", "statusCode", "size", "words", "lines", "durationMs", "url" } } }
{ "type": "fuzzer.complete", "data": { "campaignId", "status", "completed", "errors" } }
{ "type": "manipulate.ws.frame", "data": { "sessionId", "direction": "sent|received", "opcode", "payload" (base64), "isText", "size", "ts" } }
{ "type": "manipulate.ws.closed", "data": { "sessionId", "reason" } }
{ "type": "system.update.restarting", "data": {} }
{ "type": "plugin.{name}.{eventType}", "data": { ... } }
{ "type": "plugin.{name}.interaction", "data": { "id", "instanceId", "hex", "protocol", "sourceIp", "timestamp", "queryName?", "queryType?", "method?", "path?", "rawRequest?" } }
```

---

## Go Dependencies

| Module | Purpose |
|--------|---------|
| `github.com/hashicorp/go-uuid` | UUID generation for shell auth keys |
| `github.com/gorilla/websocket` | WebSocket server |
| `github.com/miekg/dns` | DNS server for callback listener |
| `modernc.org/sqlite` | Pure-Go SQLite (no CGO, cross-compiles) |
| `google.golang.org/grpc` | gRPC client for Sliver C2 teamserver |
| `google.golang.org/protobuf` | protowire for hand-encoded Sliver messages |
| `github.com/spf13/pflag` | POSIX-compliant CLI flag parsing |
| `github.com/BishopFox/joro/sdk` | Plugin SDK interfaces (local module via `replace` directive) |
| stdlib only for everything else | `crypto/x509`, `crypto/ecdsa`, `embed`, `net/http`, `io/fs` |

Dependencies are tracked through `go.mod` / `go.sum` only — the repo does **not** vendor (see the "no vendor/" design decision below). Builds resolve modules from the standard Go module cache.

Adding or upgrading a dependency:
```
go get <module>
go mod tidy
```
Commit `go.mod` and `go.sum` together. Do not hand-edit them.

---

## Key Design Decisions

- **No CLI mode.** All features are accessed through the web UI only. Do not add CLI flags for shell generation or execution.
- **No global variables.** Functions take parameters; globals were removed during the v0.5.0 restructure.
- **No `os.Exit` in packages.** Only `main.go` may exit. Internal packages return errors.
- **Intercept uses per-request channels.** `InterceptQueue.Pause()` blocks the proxy goroutine until `Resolve()` is called or the timeout fires (default 60s). Do not change this to polling.
- **CA cert is reused across restarts.** `cert.LoadOrCreate()` loads from `~/.joro/` if it exists. Only regenerates when missing.
- **`web/dist/` is embedded into the binary** via `//go:embed dist`. A placeholder `index.html` exists so `go build` works before `npm run build` is run.
- **Noise filter is separate from scope.** `NoiseFilter` silently tunnels/forwards common browser background traffic (captive portal, telemetry, OCSP, safe browsing) without capture. Enabled by default with a curated pattern list. Checked **before** scope in the proxy flow - noisy hosts are never MITM'd regardless of scope rules.
- **Two-level scope filtering.** Level 1 (CONNECT): checks host pattern only - out-of-scope hosts are tunneled raw without MITM. Level 2 (request): checks host + method + path after TLS termination - out-of-scope requests are forwarded without capture or intercept. Disabled by default; enabled with no rules blocks everything (safe default). Exclude rules override include rules.
- **Listener mode is mutually exclusive with proxy mode.** `--listener` starts DNS + HTTP callback servers and a reduced API/UI. No CA, proxy, or intercept components are loaded. Data is stored in `~/.joro/callbacks.db` (pure-Go SQLite).
- **Token entropy:** 12 hex chars = 48 bits. Tokens are correlated by extracting the leftmost subdomain label from incoming DNS/HTTP requests.
- **Port 53 requires root/capabilities on Linux.** Use `setcap cap_net_bind_service=+ep ./joro` or iptables redirect.
- **`internal/event` package** holds the shared `WSEvent` struct to avoid circular imports between `proxy` and `callback` packages.
- **Match & Replace operates on raw bytes.** Request rules split raw dump at `\r\n\r\n` and apply header/body rules independently, then reparse. Response rules do the same. Rules run cumulatively in order. Supports `string` and `regex` match types. Targets: `request_header`, `request_body`, `response_header`, `response_body`, `ws_message`.
- **WebSocket MITM uses custom frame reader/writer** operating on raw `net.Conn` (not gorilla/websocket). Detection via `Upgrade: websocket` header. After 101 handshake, two goroutines relay frames bidirectionally. Control frames forwarded immediately; data frames accumulated until FIN, match/replace applied on complete messages, then forwarded as single frame. 16MB payload limit.
- **WebSocket Manipulate is a separate client path, not a proxy interception.** `internal/proxy/ws_manipulate.go` runs a per-session outbound dial (TCP or TLS with `InsecureSkipVerify`, honoring `TransportConfig.SOCKSDialContext()` if a SOCKS proxy is configured), writes the user's raw upgrade bytes verbatim (injecting a `Sec-WebSocket-Key` only if missing), parses the 101 response with `http.ReadResponse`, then hands the connection to a read loop that reassembles continuation frames and invokes `onFrame` per complete message. `Send` always writes a single FIN masked frame. Sessions are in-memory only and keyed by a generated ID; they are dropped on server restart and on the first read error or close frame. The user-facing transcript is streamed over the existing `/ws` hub via `manipulate.ws.frame` and `manipulate.ws.closed` events — sent frames are also broadcast so multiple UI tabs on the same session stay in sync. Match & Replace is intentionally NOT applied to Manipulate frames (what you type is what goes on the wire).
- **Custom Data is purely additive.** Unlike Match & Replace which requires a match pattern, Custom Data simply appends headers, query params, or body data to in-scope requests. Applied after Match & Replace in the proxy pipeline. Managed via `internal/proxy/customdata.go`. UI lives in the "Customize Requests" tab alongside Match & Replace.
- **Fuzzer uses a custom implementation.** Producer-consumer goroutine pool with configurable concurrency (1-100 threads) and rate limiting. Reuses `proxy.TransportConfig.Transport()` for HTTP requests (respects SOCKS, HTTP/2, keep-alive settings). Results streamed to UI via WebSocket (`fuzzer.result` events) with RAF batching on the client. Response bodies are NOT stored in results — only metrics (status, size, words, lines, duration) to keep memory bounded. Campaigns stored in memory (max 50, oldest completed evicted). Supports single-position (`FUZZ`) and multi-position (`FUZZ1`, `FUZZ2`, etc.) fuzzing. Multi-position supports three attack modes: **Spray** (same payload in all positions), **Split** (parallel iteration across per-position wordlists), **Yolo** (cartesian product of all combinations, max 10M requests). Position detection uses regex `FUZZ(\d+)` for numbered positions, falls back to plain `FUZZ`. Positions are replaced longest-label-first to avoid substring collisions (e.g., `FUZZ10` before `FUZZ1`). Matchers (whitelist) and filters (blacklist) support status, size, word count, line count, and regex criteria. Content-Length auto-update is toggleable via `updateContentLength` flag.
- **CORS is permissive** (`*`) intentionally - the proxy only listens on localhost.
- **Sliver C2 integration uses custom protobuf wire encoding** via `protowire` to avoid importing the massive Sliver dependency tree. The `internal/sliver/` package has: `wire.go` (hand-encoded proto messages), `client.go` (gRPC methods), `commands.go` (command dispatcher). The dispatcher parses text commands from the UI command bar, routes to the appropriate gRPC RPC, and returns formatted text output. Binary data (downloads, screenshots) is cached server-side with a 60s TTL. The `POST /api/v1/sliver/command` endpoint is the main interface — it accepts `{input}` and returns `{output, error, downloadId?, filename?}`. Active session tracking is server-side (`Client.activeSessionID`).
- **Team Server mode** (`--listener --teamserver`) extends listener mode with auth and team collaboration. A 32-char hex token is generated at startup and printed to console. All teamserver API requests (except `GET /api/v1/mode`) require `Authorization: Bearer <token>`. Nicknames are sent via `X-Joro-Nickname` header. The teamserver is API-only (no frontend). The proxy connects to it via `listenerUrl` and forwards team requests using `proxyToListener()` with auth headers from settings. Team data (chat, notes) is stored in `callbacks.db` alongside callback data. Active user tracking uses the WebSocket Hub's client map (conn -> nickname). The proxy maintains a WebSocket relay (`ws_relay.go`) to the teamserver that forwards `team.*` events to the local hub for real-time updates. Nickname changes go through `POST /api/v1/team/nickname` which atomically renames the caller's entry in the hub's clients map and broadcasts a `team.nickname_changed` event, avoiding the visible disconnect/reconnect pair that a full relay restart would produce; the relay's cached nickname is updated via `ListenerRelay.SetNickname()` without reconnecting. If the teamserver rejects the rename (409 — name collision), the proxy rolls back the local `teamNickname` setting and surfaces the error to Settings.tsx. The Team Chat client intentionally does NOT fetch history on load — operators see only messages that arrive via WebSocket after their session started. System announcements (`[*] X connected!`, `[*] X disconnected`, `[*] X changed nickname to Y`) are synthetic client-side entries generated in `teamStore` from `team.presence` diffs and `team.nickname_changed` events; they live in the Zustand store and persist across Dashboard tab switches but not across page reloads.
- **Plugin system uses Go's `plugin` package** for shared object loading (.so on Linux, .dylib on macOS). Plugins are loaded at startup from `~/.joro/plugins/`. Each plugin exports a `var Plugin sdk.Plugin` symbol. The SDK lives in `sdk/sdk.go` as a separate Go module (`replace` directive in go.mod). Six plugin types: `exec_provider` (Execute tab integration), `tab` (top-level nav tab), `feature` (sub-tab in Plugins page), `proxy_hook` (request/response pipeline), `dashboard` (replaces default Dashboard — only one active), `interact_provider` (Interact tab OOB callback source — manages instances + interactions, renders as a flex-wrapped row of inputs below the native SSRF/XSS config bar, merges interactions into the unified Callbacks event feed via `plugin.{name}.interaction` broadcast). Plugin names must match `^[a-z0-9][a-z0-9_-]*$` and cannot be reserved words (`api`, `ws`, `ext`, `system`). All plugin method calls are wrapped with panic recovery. Plugins get a scoped data directory (`~/.joro/plugin-data/{name}/`) and a scoped WebSocket broadcast channel (events auto-prefixed with `plugin.{name}.`). Tab/feature/dashboard plugins serve embedded UIs at `/plugin/{name}/` rendered in sandboxed iframes (`allow-scripts allow-forms`). API calls from plugin iframes work because CORS is `*`. Upload/delete require a restart to take effect — the Plugins page shows a "Restart Now" button that triggers `POST /api/v1/system/restart` (same `syscall.Exec` re-exec mechanism as updates). Proxy hooks run in load order; `OnRequest` can return nil to drop a request. `ConfigField.Type` accepts `text | password | textarea | file | checkbox`; checkboxes serialize as the strings `"true"` / `"false"` to preserve the `map[string]string` wire shape.
- **Plugin state persistence is opt-in via two SDK interfaces** — `UserStatefulPlugin` (`ExportUserState`/`ImportUserState`) for operator-scoped state that rides with User Configs (API keys, personal tokens), and `ProjectStatefulPlugin` (`ExportProjectState`/`ImportProjectState`) for engagement-scoped state that rides with Project Configs (active sessions, instance configs). A plugin may implement either, both, or neither. State bytes are opaque — plugins own their own schema and migration. No autosave on shutdown and no separate on-disk state files: state is serialized only when the user explicitly saves a User or Project Config, and applied only on load. `internal/plugins/manager.go` exposes `ExportUserStates` / `ApplyUserStates` / `ExportProjectStates` / `ApplyProjectStates`. The config handlers in `internal/api/handlers_configs.go` embed a `pluginStates` map (plugin name → base64 blob) in both `userConfigFile` (v2) and `projectConfigFile` (v3), and ghost-preserve blobs for plugins not installed on the current machine via `APIServer.pendingUserPluginStates` / `pendingProjectPluginStates`, so a load→save round-trip never drops state for missing plugins. Load responses include `unknownPluginStates: []` surfaced in the Settings page.
- **Interactsh support is shipped as an example plugin** (`examples/plugins/interactsh/`), not native code. The plugin reimplements the interactsh wire protocol using only the Go standard library — RSA-2048 keygen, RSA-OAEP-SHA256 for the session AES-256 key, AES-CTR for per-interaction payloads, per-instance `http.Client` with opt-in `InsecureSkipVerify` for self-signed self-hosted servers. The main binary has zero `projectdiscovery/*` dependencies. Interactsh implements `ProjectStatefulPlugin` (see `examples/plugins/interactsh/state.go`): saving a project persists each server's RSA keypair (PKCS#1 PEM), correlation ID, nonce, secret key, auth token, and enabled state; loading reconstructs servers and resumes polling without re-registering on the remote, so in-flight interactions keep decrypting against the existing session. Correlation IDs remain useful only as long as the remote interactsh server retains them (typically ~24h on oast.live).
- **No `vendor/` directory.** The repo tracks deps through `go.mod` / `go.sum` only. Plugins have their own `go.mod` with `replace github.com/BishopFox/joro/sdk => ../../../sdk`, so they build in mod-mode. If the main binary were built in vendor-mode, its module graph would hash differently than the plugin's and Go's plugin loader would reject the resulting .so/.dylib with `plugin was built with a different version of package github.com/BishopFox/joro/sdk`. Do not run `go mod vendor` or re-commit a `vendor/` tree.
- **Theming uses CSS custom properties + `data-theme` attribute.** See the "Theme Architecture" section below.

---

## Theme Architecture

The UI ships the **Bishop Fox** theme (the BF brand palette, id `bishop-fox`) as the default, alongside a large set of named alternates. Colors are defined as CSS custom properties on `[data-theme="..."]` selectors, then mapped to semantic Tailwind classes via `tailwind.config.js`.

### Brand Palette (16 colors)

| Hex | Name |
|-----|------|
| `#FFFFFF` | White |
| `#000000` | Black |
| `#FA4844` | Red |
| `#BF1363` | Magenta |
| `#E40505` | Crimson |
| `#EF5B5B` | Coral |
| `#FF7F11` | Orange |
| `#FFBA49` | Amber |
| `#D7E300` | Lime |
| `#00A49E` | Teal |
| `#D0CFCF` | Light gray |
| `#7A7D7D` | Medium gray |
| `#565254` | Dark gray |
| `#403233` | Brown-gray |
| `#3D1308` | Dark brown |
| `#220901` | Near-black |

### CSS Variable → Tailwind Class Mapping

| CSS Variable | Tailwind Class | Usage |
|---|---|---|
| `--color-surface-body` | `bg-surface-body` | Page background |
| `--color-surface-card` | `bg-surface-card` | Cards, panels, header |
| `--color-surface-input` | `bg-surface-input` | Inputs, elevated surfaces |
| `--color-surface-hover` | `bg-surface-hover` | Hover backgrounds |
| `--color-surface-terminal` | `bg-surface-terminal` | Terminal background |
| `--color-border` | `border-border` | Borders |
| `--color-border-subtle` | `border-border-subtle` | Subtle row separators |
| `--color-content-primary` | `text-content-primary` | Primary text |
| `--color-content-secondary` | `text-content-secondary` | Secondary text |
| `--color-content-muted` | `text-content-muted` | Muted/placeholder text |
| `--color-accent` | `text-accent`, `bg-accent` | Primary accent - red (title, selected tabs, toggles) |
| `--color-accent-hover` | `bg-accent-hover` | Primary accent hover (coral) |
| `--color-accent-secondary` | `text-accent-secondary`, `bg-accent-secondary` | Secondary accent - teal (action buttons, links) |
| `--color-accent-secondary-hover` | `bg-accent-secondary-hover` | Secondary accent hover |
| `--color-accent-tertiary` | `text-accent-tertiary`, `bg-accent-tertiary` | Tertiary accent - lime (forward/generate actions) |
| `--color-accent-tertiary-hover` | `bg-accent-tertiary-hover` | Tertiary accent hover |
| `--color-semantic-success` | `text-semantic-success` | Success states (lime) |
| `--color-semantic-error` | `text-semantic-error` | Error text (red) |
| `--color-semantic-error-bg` | `bg-semantic-error-bg` | Error button bg (crimson) |
| `--color-semantic-error-hover` | `bg-semantic-error-hover` | Error button hover (coral) |
| `--color-semantic-info` | `text-semantic-info` | Info states (teal) |
| `--color-semantic-warning` | `text-semantic-warning` | Warning states (amber) |
| `--color-semantic-special` | `text-semantic-special` | Special accent (magenta) |

### How Theming Works

1. `web/index.html` has `data-theme="bishop-fox"` on `<html>`
2. Each `web/src/themes/<name>.css` defines CSS variables under a `[data-theme="<name>"]` selector
3. `web/tailwind.config.js` maps semantic class names to `var(--color-*)` references
4. Components use semantic classes (`bg-surface-card`, `text-accent`) - never raw Tailwind colors

### How to Add a New Theme

1. Create `web/src/themes/<name>.css` with all `--color-*` variables under `[data-theme="<name>"]`
2. Import it in `web/src/index.css`
3. Set `data-theme="<name>"` on `<html>` to activate

### Important Notes

- **No raw Tailwind colors in components.** Do not use `bg-gray-*`, `text-red-*`, etc. in TSX files. Always use semantic classes.
- **Three accent colors:** Red (`accent`) for brand/emphasis/selected states, Teal (`accent-secondary`) for action buttons and links, Lime (`accent-tertiary`) for positive/forward actions. The primary accent is Red (`#FA4844`) to align with the BF brand palette.
- **`bg-accent-tertiary` and `bg-accent-secondary` buttons need `text-black`** for legibility on light-colored backgrounds.
- **Tailwind opacity syntax (`bg-color/80`) won't work** with CSS variable colors. Use a dedicated variable or a different palette color for opacity variations.
- **CodeMirror uses `oneDark` theme** - not yet integrated with the theming system.
- **Theme selector** is on the Settings page. Selection is stored in `localStorage` under `joro-theme` and applied on page load in `main.tsx`.

---

## Testing

There are no automated tests yet. Manual verification steps:

1. `go build ./...` - must compile cleanly with no errors
2. Run `./joro` - prints `Proxy listening on :8080` and `UI available at http://localhost:9090`
3. Configure browser proxy to `localhost:8080`, import `~/.joro/ca.crt` into trust store
4. Browse any HTTPS site - requests appear in History tab
5. Enable Intercept - next request pauses; edit and forward
6. Manipulate (HTTP) - paste raw request, send, view response with timing
6a. Manipulate (WebSocket) - switch to the WebSocket sub-tab, enter `wss://echo.websocket.events/`, edit the upgrade headers if desired, click Connect, send a text frame, verify the echo appears in the transcript. Repeat with Binary (hex) and Ping opcodes. Disconnect to close the session.
7. Generate - select PHP (or ASHX for an IIS target), generate shell, verify auth key + content
8. Execute - enter target + shell path + auth key, run `whoami`
9. Plugins - build an example plugin (`./joro --build-plugin examples/plugins/hello-feature --install`), restart, verify it loads in the Plugins tab
10. Upload a plugin via the Plugins tab, click "Restart Now", verify it loads after restart
