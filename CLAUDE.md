# Joro - Claude Code Instructions

## Keeping This File Fresh

**Update this file whenever significant changes are made to the project** - new packages, changed commands, architectural decisions, or new conventions. Outdated instructions cause mistakes. If you add a dependency, change a build step, or restructure a package, update the relevant section here before finishing the task.

---

## Project Overview

Joro is an intercepting HTTP/HTTPS proxy and web shell toolkit for penetration testing. It is a single Go binary that starts a proxy server and serves a React web UI - there is no CLI mode.

Three modes:
- **Proxy mode** (default): intercepting proxy + web UI
- **Listener mode** (`--listener`): out-of-band callback server (DNS + HTTP + SMTP) for blind vuln detection
- **Team Server mode** (`--listener --teamserver`): listener + authenticated team collaboration (chat, notes)

Ports & paths:
- Proxy `:8080` (`--proxy-port`), UI/API `:9090` (`--ui-port`)
- Data dir `~/.joro/` — CA cert/key + `callbacks.db`
- Listener: DNS `:53` (`--dns-port`), HTTP `:80` (`--http-port`), HTTPS `:443` (`--https-port`, `0` to disable), SMTP `:25` (`--smtp-port`, `0` to disable), SMTPS `:465` (`--smtps-port`, `0` to disable), domain via `--domain` or UI, optional external TLS cert via `--tls-cert` + `--tls-key` (both required; replaces the auto-generated self-signed leaf, shared by HTTPS and SMTPS/STARTTLS)

---

## Repository Structure

```
main.go                      Entrypoint (proxy or listener mode)
internal/
  config/                    Config struct + defaults
  event/                     Shared WSEvent struct (avoids proxy/callback import cycle)
  callback/                  SQLite (modernc.org/sqlite), token CRUD, DNS + HTTP listeners
  cert/                      ECDSA P-256 CA, leaf gen, sync.Map cache
  proxy/
    handler.go               ServeHTTP: CONNECT vs plain HTTP
    mitm.go                  TLS termination + HTTP/1.1 loop
    intercept.go             Per-request channel queue with timeout
    noise.go                 Silently tunnels browser background traffic
    scope.go                 Two-level scope (host + method/path)
    store.go                 Thread-safe ring buffer
    replace.go               Match & Replace (raw-byte rules)
    customdata.go            Additive header/query/body injection
    websocket.go ws_relay.go ws_store.go   WS MITM (custom frames over net.Conn)
    ws_manipulate.go         User-driven outbound WS sessions
    client.go helpers.go     HTTP client + utilities
  team/                      Team chat + notes tables, bearer-token auth middleware
  fuzzer/                    Goroutine-pool fuzzer + in-memory campaign store (max 50)
  shell/                     ASP/ASPX/PHP/etc. shell gen + executor + dictionary
  sliver/                    gRPC client for Sliver C2 (custom protowire encoding)
  plugins/                   Plugin lifecycle: load, categorize, init, shutdown
  api/
    server.go routes.go      APIServer + route registration + SPA embedding
    ws.go                    WebSocket hub (gorilla/websocket)
    handlers_*.go            Per-feature handlers (requests, intercept, manipulate,
                             generate, execute, fuzzer, settings, certs, callbacks,
                             replace, customdata, plugins, team, sliver, ws, ...)
    ws_relay.go              Relay to teamserver, forwards team.* events
sdk/sdk.go                   Plugin SDK: interfaces, types, constants (separate Go module)
web/
  embed.go                   //go:embed dist
  dist/                      Built frontend (gitignored except placeholder)
  src/
    main.tsx App.tsx index.css vite-env.d.ts
    themes/bishop-fox.css    Default dark theme (BF brand palette)
    lib/api.ts ws.ts         Typed fetch wrapper + WS singleton (auto-reconnect)
    stores/*.ts              Zustand: request, fuzz, intercept, settings, callback,
                             ws, manipulateWS, team
    pages/                   History, Intercept, Manipulate (HTTP+WS), Generator,
                             Executor, Fuzz, Login, Settings, Callbacks, Plugins,
                             PluginTabPage
    components/              DynamicConfigForm (auto-gen plugin ExecProvider config)
examples/plugins/
  hello-provider/            ExecProvider + GraphProvider example
  hello-tab/ hello-feature/  Top-level tab + sub-tab plugin examples
  hello-dashboard/           Dashboard replacement example
  interactsh/                InteractProvider: stdlib-only interactsh client
Makefile                     build, build-frontend, build-all, dev, clean
```

---

## Build Commands

```bash
go build ./...               # Go-only (uses placeholder frontend, works without npm)
make build                   # Full (frontend + Go binary)
make build-all               # Cross-platform → dist/
make dev                     # Backend with --dev flag (proxies UI to Vite)
cd web && npm run dev        # Vite dev server (separate terminal, with `make dev`)

# Build a plugin from source (auto-detects .so vs .dylib)
./joro --build-plugin examples/plugins/hello-feature
./joro --build-plugin examples/plugins/hello-feature --install   # also installs to ~/.joro/plugins/

# Or manually:
cd examples/plugins/hello-feature
go build -buildmode=plugin -o hello-feature.dylib .   # macOS
go build -buildmode=plugin -o hello-feature.so .      # Linux
```

### Releases

Tagged releases use [goreleaser](https://goreleaser.com) (config: `.goreleaser.yaml`). `make build` / `make build-all` are the local-dev workflow; goreleaser is only for cutting releases.

```bash
goreleaser release --snapshot --clean   # Local snapshot — sanity check config
goreleaser check                        # Verify config syntax
git tag v1.0.1 && git push --tags && goreleaser release --clean   # Cut release (needs GITHUB_TOKEN)
```

Goreleaser produces 6 binaries (linux/{amd64,arm64}, darwin/{amd64,arm64}, windows/{amd64,arm64}) in tar.gz/zip archives with LICENSE + README, plus `checksums.txt`. All targets are built with `CGO_ENABLED=1` via `zig cc` cross-compilers — required so Go's `plugin` package (dlopen-based) works in release binaries. `make build-all` mirrors the goreleaser config (also CGO=1 + zig cc) and produces all 6 targets. **Requires `zig` on PATH** (`brew install zig`); the goreleaser `before:` hook fails fast if it's missing. Linux glibc is pinned to 2.17 for wide compat. Releases are created as **drafts** so the operator publishes manually. `-X main.version={{.Tag}}` and `-X main.commit={{.ShortCommit}}` are injected at link time. Asset name template (`joro_<version>_<os>_<arch>.tar.gz|zip`) is duplicated in `internal/update/update.go` (`runBinaryUpdate`) — keep them in sync.

**`--build-plugin` flag forwarding.** `runBuildPlugin` in `main.go` reads `runtime/debug.BuildInfo` from the running binary and forwards ABI-relevant settings to the child `go build -buildmode=plugin`: `-trimpath`, `-tags` (e.g. `netgo,osusergo`), and `CGO_ENABLED` / `GOARM64` / `GOAMD64` env. Without this, a release host (built with `-trimpath -tags netgo,osusergo`) and a plugin built bare hash stdlib packages differently, and dlopen rejects with `plugin was built with a different version of package internal/goarch`. The build banner prints the resolved `Flags:` and `Env:` so mismatches are visible. If a plugin still fails to load with `different version of package …`, check that `go version` (run from the plugin's source dir) matches the host binary's `runtime.Version()`.

**Plugin go.mod must require the SDK at the host's pseudo-version.** Under `-trimpath`, the Go compiler bakes the SDK's module version string into the position info embedded in exported declarations, which is part of the package's export hash (`go:link.pkghashbytes.github.com/BishopFox/joro/sdk`). The host's `go.mod` requires `github.com/BishopFox/joro/sdk v0.0.0-00010101000000-000000000000` (Go's canonical zero pseudo-version, auto-generated by `go mod tidy` for a local-replace dep with no real tag). A plugin `go.mod` that requires plain `v0.0.0` will produce a different export hash even though the source files and replace target are identical, and `plugin.Open()` will reject with `different version of package github.com/BishopFox/joro/sdk`. The 5 example plugin go.mod files all use the full pseudo-version — do the same in any new plugin. Without `-trimpath`, the issue is masked because position info uses absolute filesystem paths that happen to match across both builds, so `make build` + `--build-plugin` works without the version match; only release (goreleaser) builds expose the bug.

### In-app updater install modes

`internal/update/update.go` detects how the running binary was installed:
- **Git mode** (`.git` dir alongside executable): `git fetch` + parse upstream `main.go` version literal; update via `git pull --ff-only` + `make build`.
- **Binary mode** (no `.git`): hits `GET /repos/BishopFox/joro/releases/latest`, downloads matching archive + `checksums.txt`, verifies SHA-256, atomically replaces the running binary.

Both paths fail silently on errors (no network, rate limit, missing `git`, bad checksum) — startup is never blocked. After successful update, `update.Restart()` re-execs.

---

## Frontend Development

Source in `web/`. TypeScript/React/Vite.

```bash
cd web
npm install       # install dependencies
npm run dev       # Vite dev server on :5173 (use with `make dev`)
npm run build     # output to web/dist/ (embedded into Go binary)
```

**npm registry:** machine may be on a private registry. If `npm install` fails, check `npm config get registry` and `npm config delete registry`.

---

## API Reference

All under `/api/v1/`. Request/response shapes are JSON unless noted. WebSocket events stream from `/ws`.

**History & intercept**
- `GET/DELETE /requests`, `GET /requests/:id` — paginated history with filters; raw bytes base64
- `GET /intercept`, `PUT /intercept/enabled`, `POST /intercept/:id/{forward,drop}` — queue control; forward accepts modified `reqRaw` base64

**Manipulate**
- `POST /manipulate/send` — raw HTTP `{raw b64, scheme, host}`
- `POST /manipulate/ws/connect` — `{raw b64, scheme: ws|wss, host}` → `{sessionId, status, rawResp, error}` (always 200; sessionId empty on failure)
- `POST /manipulate/ws/{id}/send` — `{opcode: text|binary|ping|pong|close, payload b64}`
- `POST /manipulate/ws/{id}/disconnect`

**Shells**
- `POST /generate` — `{format: php|asp|aspx|ashx|jsp|cfm}`
- `POST /execute` — `{target, webshell, authKey, command}`

**Fuzzer**
- `POST /fuzzer/start` — `{raw, scheme, host, wordlist[], wordlists?, attackMode?, threads, rateLimit, followRedirects, updateContentLength?, matchers, filters}`
- `POST /fuzzer/{id}/stop`, `GET /fuzzer/campaigns`, `GET /fuzzer/campaigns/{id}` (paginated results), `DELETE /fuzzer/campaigns/{id}`
- `POST /fuzzer/wordlist` — multipart upload → `{lines[], count}`

**Filters & rules** (each: `GET`, `PUT /enabled`, `POST` add, `DELETE /{id}`)
- `/noise` — `{pattern}`
- `/scope/rules` — `{pattern, methods, path, include}`
- `/replace/rules` — `{target, matchType, match, replace}` (target ∈ request_header, request_body, response_header, response_body, ws_message)
- `/customdata/items` — `{type, name, value}`

**WebSocket capture**
- `GET /ws/messages?host=&offset=&limit=`, `DELETE /ws/messages`

**Settings & system**
- `GET/PUT /settings`, `GET /certs/ca.crt`, `GET /mode` (returns `{mode: proxy|listener}`)
- `POST /system/restart` — graceful re-exec

**Callbacks (listener mode)**
- `GET/PUT /callbacks/config` — `{domain, responseIp}`
- `GET/POST /callbacks/tokens`, `DELETE /callbacks/tokens/{id}` (cascade)
- `GET/DELETE /callbacks/interactions?token_id=`

**Sliver C2**
- `GET /sliver/status`, `POST /sliver/{connect,disconnect}`, `GET /sliver/sessions`
- `POST /sliver/execute` — `{sessionId, command, args}`
- `POST /sliver/command` — `{input}` → `{output, error, downloadId?, filename?}` (text command dispatcher)
- `GET /sliver/download/{id}` (60s TTL cache), `POST /sliver/upload` (multipart)

**Team server** (auth: `Authorization: Bearer <token>` + `X-Joro-Nickname`)
- `GET/POST /team/chat`, `GET /team/users`, `POST /team/nickname` (`{oldNickname, newNickname}`)
- `GET /team/notes/hosts`, `GET/POST /team/notes`, `DELETE /team/notes/{id}`

**Plugins**
- `GET /plugins`, `POST /plugins/upload` (multipart, 32MB max), `DELETE /plugins/{filename}` (restart required)
- `GET /plugins/{exec-providers,interact-providers,graph}`
- Per-plugin exec: `GET /plugin/{name}/status`, `POST /plugin/{name}/{connect,disconnect,command}`
- Per-plugin interact: `GET/POST /plugin/{name}/interact/instances`, `DELETE /plugin/{name}/interact/instances/{id}`, `PUT .../enabled`, `GET/DELETE /plugin/{name}/interact/interactions?instance_id=`

### WebSocket Events (over `/ws`)

```
request.captured          { ...RequestSummary }
intercept.queued          { id, method, url, host, reqRaw }
intercept.resolved        { id, action: forward|drop }
callback.interaction      { ...Interaction }
ws.message                { id, connectionId, timestamp, direction, opcode, payloadLength, payload, host, url, isText }
team.chat                 { id, author, text, createdAt }
team.note                 { id, host, content, author, createdAt, updatedAt }
team.presence             { users: [...] }
team.nickname_changed     { oldNickname, newNickname }
fuzzer.started            { campaignId, total }
fuzzer.result             { campaignId, result: { index, payload, payloads?, statusCode, size, words, lines, durationMs, url } }
fuzzer.complete           { campaignId, status, completed, errors }
manipulate.ws.frame       { sessionId, direction: sent|received, opcode, payload (b64), isText, size, ts }
manipulate.ws.closed      { sessionId, reason }
system.update.restarting  {}
plugin.{name}.{eventType} { ... }
plugin.{name}.interaction { id, instanceId, hex, protocol, sourceIp, timestamp, queryName?, queryType?, method?, path?, rawRequest? }
```

---

## Go Dependencies

| Module | Purpose |
|--------|---------|
| `github.com/hashicorp/go-uuid` | UUIDs for shell auth keys |
| `github.com/gorilla/websocket` | WebSocket server |
| `github.com/miekg/dns` | DNS server (callback listener) |
| `modernc.org/sqlite` | Pure-Go SQLite (no CGO, cross-compiles) |
| `google.golang.org/grpc` + `google.golang.org/protobuf` | Sliver C2 client (protowire hand-encoded) |
| `github.com/spf13/pflag` | POSIX-compliant CLI flags |
| `github.com/BishopFox/joro/sdk` | Plugin SDK (local module via `replace`) |
| stdlib for everything else | `crypto/x509`, `crypto/ecdsa`, `embed`, `net/http`, `io/fs`, ... |

Tracked via `go.mod` / `go.sum` only — repo does **not** vendor (see "no vendor/" decision below). Add deps with `go get <module>` then `go mod tidy`. Commit `go.mod` + `go.sum` together. Do not hand-edit them.

---

## Key Design Decisions

- **No CLI mode.** All features through web UI. Don't add CLI flags for shell gen/exec.
- **No global variables.** Functions take parameters; globals removed in v0.5.0.
- **No `os.Exit` in packages.** Only `main.go` exits. Internal packages return errors.
- **Intercept uses per-request channels.** `InterceptQueue.Pause()` blocks the proxy goroutine until `Resolve()` or timeout (default 60s). Don't change to polling.
- **CA cert reused across restarts.** `cert.LoadOrCreate()` only regenerates when missing.
- **`web/dist/` embedded** via `//go:embed dist`. Populated by `npm run build` before Go compiles — `make build` runs the frontend first, and the goreleaser `before:` hook does the same. Bare `go build ./...` requires `npm run build` to have run.
- **Noise filter is separate from scope.** Silently tunnels common browser background traffic (captive portal, telemetry, OCSP, safe browsing) without capture. Enabled by default. Checked **before** scope — noisy hosts never MITM'd regardless of scope rules.
- **Two-level scope filtering.** L1 (CONNECT): host pattern only — out-of-scope hosts tunneled raw without MITM. L2 (request): host + method + path after TLS termination — out-of-scope requests forwarded without capture/intercept. Disabled by default; enabled with no rules blocks everything (safe default). Exclude rules override include rules.
- **Listener mode is mutually exclusive with proxy mode.** `--listener` starts DNS + HTTP callback servers + reduced API/UI. No CA, proxy, or intercept. Data in `~/.joro/callbacks.db`.
- **Token entropy:** 12 hex chars = 48 bits. Correlated by leftmost subdomain label.
- **Privileged ports need root/capabilities on Linux.** DNS `:53`, SMTP `:25`, HTTP `:80`, HTTPS `:443`, SMTPS `:465` are all <1024. `setcap cap_net_bind_service=+ep ./joro` or iptables redirect; or use the `--{dns,http,https,smtp,smtps}-port` flags to pick unprivileged ports.
- **`internal/event` package** holds shared `WSEvent` to avoid proxy↔callback import cycle.
- **Match & Replace operates on raw bytes.** Splits raw dump at `\r\n\r\n`, applies header/body rules independently, then reparses. Cumulative in order. Supports `string` and `regex`. Targets: `request_header`, `request_body`, `response_header`, `response_body`, `ws_message`.
- **WebSocket MITM uses custom frame reader/writer** on raw `net.Conn` (not gorilla). Detected via `Upgrade: websocket`. After 101, two goroutines relay bidirectionally. Control frames forwarded immediately; data frames accumulated until FIN, match/replace applied on complete messages, forwarded as single frame. 16MB payload limit.
- **WebSocket Manipulate is a client path, not proxy interception.** `internal/proxy/ws_manipulate.go` dials per-session (TCP or TLS w/ `InsecureSkipVerify`, honoring `TransportConfig.SOCKSDialContext()`), writes raw upgrade verbatim (injects `Sec-WebSocket-Key` only if missing), parses 101 with `http.ReadResponse`, reassembles continuation frames, calls `onFrame` per complete message. `Send` writes a single FIN masked frame. Sessions in-memory only, dropped on restart/error/close. Transcript streamed via `manipulate.ws.frame`/`manipulate.ws.closed` — sent frames also broadcast so multiple UI tabs stay in sync. Match & Replace intentionally NOT applied — what you type is what goes on the wire.
- **Custom Data is purely additive.** Unlike Match & Replace (needs match pattern), Custom Data appends headers, query params, or body data to in-scope requests. Applied after Match & Replace. UI in "Customize Requests" tab.
- **Fuzzer:** producer-consumer goroutine pool, 1-100 threads, rate limiting. Reuses `proxy.TransportConfig.Transport()` (SOCKS, HTTP/2, keep-alive). Results streamed via `fuzzer.result` with RAF batching client-side. Response bodies NOT stored — only metrics (status, size, words, lines, duration). Campaigns in memory (max 50, oldest completed evicted). Single (`FUZZ`) or multi-position (`FUZZ1`, `FUZZ2`, ...). Multi-position attack modes: **Spray** (same payload all positions), **Split** (parallel iteration), **Yolo** (cartesian product, max 10M). Detection regex `FUZZ(\d+)` with fallback to `FUZZ`. Replaced longest-label-first (e.g. `FUZZ10` before `FUZZ1`). Matchers (whitelist) / filters (blacklist) on status, size, words, lines, regex. Content-Length auto-update toggled by `updateContentLength`.
- **Proxy-mode API enforces same-origin requests** (`internal/api/originguard.go`). `originGuard` rejects state-changing requests (and the `/ws` upgrade) unless `Sec-Fetch-Site` is `same-origin`/`none` and any `Origin` matches the host, plus a loopback/`--bind` `Host` allowlist. No `Access-Control-Allow-Origin` header is set (the SPA and plugin iframes are same-origin; the proxy→teamserver path is a non-browser Go client). Non-browser local tooling (no `Sec-Fetch-Site`/`Origin`) is allowed. Listener/team-server mode uses `team.AuthMiddleware`'s bearer token instead (no origin guard).
- **Sliver C2 uses custom protowire encoding** to avoid the massive Sliver dep tree. `internal/sliver/`: `wire.go` (hand-encoded proto), `client.go` (gRPC), `commands.go` (text command dispatcher). Binary downloads/screenshots cached server-side, 60s TTL. `POST /sliver/command` is the main interface — `{input}` → `{output, error, downloadId?, filename?}`. Active session tracked in `Client.activeSessionID`.
- **Team Server mode (`--listener --teamserver`)** extends listener mode with auth + collaboration. 32-char hex token generated at startup, printed to console. All teamserver requests (except `GET /api/v1/mode`) require `Authorization: Bearer <token>`. Nicknames via `X-Joro-Nickname`. Teamserver is API-only (no frontend). Proxy connects via `listenerUrl` and forwards team requests with `proxyToListener()`. Team data stored in `callbacks.db`. Active users tracked via WS hub client map (conn → nickname). Proxy maintains a WS relay (`ws_relay.go`) that forwards `team.*` events to the local hub. Nickname rename via `POST /api/v1/team/nickname` atomically renames in hub map and broadcasts `team.nickname_changed`, avoiding the disconnect/reconnect a full relay restart would cause; relay's cached nickname updated via `ListenerRelay.SetNickname()`. On 409 (collision), proxy rolls back the local `teamNickname` setting and surfaces the error. Team Chat does NOT fetch history on load — operators see only WS messages from session start. System announcements (`[*] X connected!`, etc.) are synthetic client-side entries in `teamStore` from `team.presence` diffs + `team.nickname_changed` events; persist across tab switches but not page reloads.
- **Plugin system uses Go's `plugin` package** (.so on Linux, .dylib on macOS). **Linux and macOS only** — Go's plugin package does not support Windows or any GOOS outside Linux/Darwin/FreeBSD. `joro --build-plugin` errors immediately on Windows; release binaries on Windows still load fine but cannot use plugins. Plugin support requires the host binary to be built with `CGO_ENABLED=1`; the goreleaser config + Makefile do this via `zig cc`. Loaded at startup from `~/.joro/plugins/`. Each exports `var Plugin sdk.Plugin`. SDK in `sdk/sdk.go` as separate Go module (`replace` in go.mod). Six plugin types: `exec_provider`, `tab`, `feature`, `proxy_hook`, `dashboard` (only one active), `interact_provider`. Names match `^[a-z0-9][a-z0-9_-]*$`, can't be reserved (`api`, `ws`, `ext`, `system`). All method calls wrapped with panic recovery. Plugins get scoped data dir (`~/.joro/plugin-data/{name}/`) and scoped WS broadcast (events auto-prefixed `plugin.{name}.`). Tab/feature/dashboard plugins serve embedded UIs at `/plugin/{name}/` in iframes sandboxed with `allow-scripts allow-forms allow-same-origin`. `allow-same-origin` makes their `/api/v1/*` calls genuine same-origin requests (so they pass `originGuard` with no plugin code changes); it's safe because plugins are already trusted native code running in-process, so the iframe sandbox was never a real boundary against them. Upload/delete require restart — Plugins page has "Restart Now" button (`POST /api/v1/system/restart`, same `syscall.Exec` re-exec as updates). Proxy hooks run in load order; `OnRequest` returning nil drops a request. `ConfigField.Type` ∈ `text|password|textarea|file|checkbox`; checkboxes serialize as `"true"`/`"false"` to preserve `map[string]string` wire shape.
- **Plugin state persistence is opt-in via two SDK interfaces.** `UserStatefulPlugin` (`ExportUserState`/`ImportUserState`) — operator-scoped state riding with User Configs (API keys, personal tokens). `ProjectStatefulPlugin` (`ExportProjectState`/`ImportProjectState`) — engagement-scoped state riding with Project Configs (active sessions, instance configs). May implement either, both, or neither. State bytes are opaque — plugins own schema and migration. No autosave on shutdown, no separate on-disk state files: serialized only when user saves a User/Project Config, applied only on load. `internal/plugins/manager.go` exposes `{Export,Apply}{User,Project}States`. Config handlers in `internal/api/handlers_configs.go` embed a `pluginStates` map (name → base64 blob) in `userConfigFile` (v2) and `projectConfigFile` (v3), and ghost-preserve blobs for plugins not installed locally via `APIServer.pendingUserPluginStates` / `pendingProjectPluginStates`, so a load→save round-trip never drops state for missing plugins. Load responses include `unknownPluginStates: []` shown in Settings.
- **Interactsh shipped as an example plugin** (`examples/plugins/interactsh/`), not native. Reimplements interactsh wire protocol with stdlib only — RSA-2048 keygen, RSA-OAEP-SHA256 for session AES-256 key, AES-CTR for per-interaction payloads, per-instance `http.Client` with opt-in `InsecureSkipVerify` for self-signed self-hosted servers. Main binary has zero `projectdiscovery/*` deps. Implements `ProjectStatefulPlugin` (`state.go`): saves RSA keypair (PKCS#1 PEM), correlation ID, nonce, secret key, auth token, enabled state per server. Loading reconstructs servers and resumes polling without re-registering, so in-flight interactions keep decrypting against the existing session. Correlation IDs only useful while the remote server retains them (~24h on oast.live).
- **No `vendor/` directory.** Tracked via `go.mod`/`go.sum` only. Plugins have own `go.mod` with `replace github.com/BishopFox/joro/sdk => ../../../sdk`, building in mod-mode. If the main binary built in vendor-mode, its module graph would hash differently than the plugin's and Go's plugin loader would reject the .so/.dylib with `plugin was built with a different version of package github.com/BishopFox/joro/sdk`. Do not run `go mod vendor` or commit a `vendor/` tree.
- **Theming uses CSS custom properties + `data-theme` attribute.** See Theme Architecture below.

---

## Theme Architecture

UI ships **Bishop Fox** theme (BF brand palette, id `bishop-fox`) as default, alongside named alternates. Colors are CSS custom properties on `[data-theme="..."]` selectors, mapped to semantic Tailwind classes via `tailwind.config.js`.

Brand palette uses 16 colors — White, Black, Red `#FA4844`, Magenta `#BF1363`, Crimson `#E40505`, Coral `#EF5B5B`, Orange `#FF7F11`, Amber `#FFBA49`, Lime `#D7E300`, Teal `#00A49E`, plus 6 grays/browns from light gray to near-black.

### CSS Variable → Tailwind Class Mapping

| CSS Variable | Tailwind Class | Usage |
|---|---|---|
| `--color-surface-body` | `bg-surface-body` | Page background |
| `--color-surface-card` | `bg-surface-card` | Cards, panels, header |
| `--color-surface-input` | `bg-surface-input` | Inputs, elevated surfaces |
| `--color-surface-hover` | `bg-surface-hover` | Hover backgrounds |
| `--color-surface-terminal` | `bg-surface-terminal` | Terminal background |
| `--color-border`, `--color-border-subtle` | `border-border`, `border-border-subtle` | Borders, row separators |
| `--color-content-{primary,secondary,muted}` | `text-content-{primary,secondary,muted}` | Text |
| `--color-accent` (+`-hover`) | `text-accent`, `bg-accent` | Primary — red (title, selected tabs, toggles) |
| `--color-accent-secondary` (+`-hover`) | `text-accent-secondary`, `bg-accent-secondary` | Secondary — teal (action buttons, links) |
| `--color-accent-tertiary` (+`-hover`) | `text-accent-tertiary`, `bg-accent-tertiary` | Tertiary — lime (forward/generate actions) |
| `--color-semantic-success` | `text-semantic-success` | Lime |
| `--color-semantic-error` (+`-bg`, `-hover`) | `text-semantic-error`, `bg-semantic-error-bg`, `bg-semantic-error-hover` | Red text / crimson bg / coral hover |
| `--color-semantic-info` | `text-semantic-info` | Teal |
| `--color-semantic-warning` | `text-semantic-warning` | Amber |
| `--color-semantic-special` | `text-semantic-special` | Magenta |

### How It Works

1. `web/index.html` has `data-theme="bishop-fox"` on `<html>`
2. Each `web/src/themes/<name>.css` defines variables under `[data-theme="<name>"]`
3. `web/tailwind.config.js` maps semantic classes to `var(--color-*)`
4. Components use semantic classes only — never raw Tailwind colors

To add a new theme: create `web/src/themes/<name>.css` with all `--color-*` variables under `[data-theme="<name>"]`, import in `web/src/index.css`, set `data-theme="<name>"` on `<html>` to activate.

### Important

- **No raw Tailwind colors in components.** No `bg-gray-*`, `text-red-*`, etc. in TSX. Always use semantic classes.
- **Three accent colors:** Red (`accent`) for brand/emphasis/selected, Teal (`accent-secondary`) for actions/links, Lime (`accent-tertiary`) for positive/forward.
- **`bg-accent-tertiary` and `bg-accent-secondary` buttons need `text-black`** for legibility.
- **Tailwind opacity syntax (`bg-color/80`) won't work** with CSS variable colors. Use a dedicated variable or a different palette color.
- **CodeMirror uses `oneDark`** — not yet integrated with theming.
- **Theme selector** on Settings page. Stored in `localStorage` under `joro-theme`, applied on load in `main.tsx`.

---

## Testing

No automated tests yet. Manual verification:

1. `go build ./...` compiles cleanly
2. `./joro` prints `Proxy listening on :8080` and `UI available at http://localhost:9090`
3. Browser proxy → `localhost:8080`; import `~/.joro/ca.crt`
4. Browse HTTPS site; requests appear in History
5. Enable Intercept; next request pauses; edit and forward
6. Manipulate (HTTP): paste raw, send, verify response + timing
7. Manipulate (WS): connect to `wss://echo.websocket.events/`, send text/binary/ping, verify echo, disconnect
8. Generate PHP/ASHX shell, verify auth key + content
9. Execute: enter target + shell + key, run `whoami`
10. Plugins: `./joro --build-plugin examples/plugins/hello-feature --install`, restart, verify load; upload via UI + "Restart Now" + verify
