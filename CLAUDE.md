# Joro - Claude Code Instructions

## Keeping This File Fresh

**Update this file whenever significant changes are made to the project** - new packages, changed commands, architectural decisions, or new conventions. Outdated instructions cause mistakes. If you add a dependency, change a build step, or restructure a package, update the relevant section here before finishing the task.

---

## Project Overview

Joro is an intercepting HTTP/HTTPS proxy and web shell toolkit for penetration testing. It is a single Go binary that starts a proxy server and serves a React web UI - there is no CLI mode.

Three modes:
- **Proxy mode** (default): intercepting proxy + web UI
- **Listener mode** (`--listener`): out-of-band callback server (DNS + HTTP + SMTP) for blind vuln detection
- **Team Server mode** (`--listener --teamserver`): listener + authenticated team collaboration (chat, notes, flagged requests, shared project configs + collaboration swap)

Ports & paths:
- Proxy `:8080` (`--proxy-port`), UI/API `:9090` (`--ui-port`)
- Data dir `~/.joro/` — CA cert/key + `callbacks.db`
- Listener: DNS `:53` (`--dns-port`), HTTP `:80` (`--http-port`), HTTPS `:443` (`--https-port`, `0` to disable), SMTP `:25` (`--smtp-port`, `0` to disable), SMTPS `:465` (`--smtps-port`, `0` to disable), FTP `:21` (`--ftp-port`, `0` to disable), FTPS `:0` (`--ftps-port`, implicit TLS, disabled by default), LDAP `:389` (`--ldap-port`, `0` to disable), LDAPS `:0` (`--ldaps-port`, implicit TLS, disabled by default), domain via `--domain` or UI, optional external TLS cert via `--tls-cert` + `--tls-key` (both required; replaces the auto-generated self-signed leaf, shared by HTTPS/SMTPS/FTPS/LDAPS and STARTTLS)

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
  detect/                    Passive vulnerability detection over captured traffic
    detect.go                Enums, Rule, Finding, Occurrence, Config, Summary
    rules_builtin.go         ~130 built-in regex rules (function, not a package var)
    analyzers.go             ~37 Go analyzers (headers, cookies, relational checks)
    postfilters.go           Named validators: luhn, iban97, ssn, denylist, ...
    entropy.go               Shannon entropy + placeholder detection
    parse.go                 Raw bytes -> Message (decompress, gate, size-cap)
    engine.go store.go       Immutable ruleSet snapshot + dedup findings store
    scanner.go               250ms cursor loop + rescan worker fan-out
  shell/                     ASP/ASPX/PHP/etc. shell gen + executor + dictionary
  sliver/                    gRPC client for Sliver C2 (custom protowire encoding)
  plugins/                   Plugin lifecycle: load, categorize, init, shutdown
  api/
    server.go routes.go      APIServer + route registration + SPA embedding
    ws.go                    WebSocket hub (gorilla/websocket)
    handlers_*.go            Per-feature handlers (requests, intercept, manipulate,
                             generate, execute, fuzzer, detect, settings, certs,
                             callbacks, replace, customdata, plugins, team, sliver, ws, ...)
    detect_loop.go           Starts the detect scanner; owns the 4 cursor-reset helpers
    detect_project.go        Detect <-> projectConfigFile DTO conversion
    ws_relay.go              Relay to teamserver, forwards team.* events
sdk/sdk.go                   Plugin SDK: interfaces, types, constants (separate Go module)
web/
  embed.go                   //go:embed dist
  dist/                      Built frontend (gitignored except placeholder)
  src/
    main.tsx App.tsx index.css vite-env.d.ts
    themes/bishop-fox.css    Default dark theme (BF brand palette)
    lib/api.ts ws.ts         Typed fetch wrapper + WS singleton (auto-reconnect)
    lib/deaddrop.ts          .jord export/import (gzip via CompressionStream, base64 raw bytes)
    lib/dashboardWidgets.tsx Dashboard widget catalog (id, availability, data needs)
    lib/dashboardPresets.tsx Layout presets + the team/local default layouts
    lib/useDashboardPolling.ts  The dashboard's single poll loop
    stores/*.ts              Zustand: request, fuzz, intercept, settings, callback,
                             ws, manipulateWS, team, teamFlagged, teamSharedConfig, deadDrop,
                             dashboardData (polled), dashboardLayout (persisted)
    pages/                   Dashboard (a frame over the widget catalog), History,
                             Intercept, Manipulate (HTTP+WS), Generator, Executor, Fuzz,
                             DeadDrop, Login, Settings, Callbacks, Plugins, PluginTabPage
    components/              DynamicConfigForm (auto-gen plugin ExecProvider config),
                             DetectRuleModal (per-rule config; opened from the
                             Detect -> Rules table, whose categories collapse),
                             DashboardPanel (shared widget chrome; slot-aware via context),
                             DashboardLayoutSettings (the layout editor)
    components/dashboard/    One file per dashboard widget
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

**`--build-plugin` flag forwarding.** `runBuildPlugin` in `main.go` reads `runtime/debug.BuildInfo` from the running binary and forwards ABI-relevant settings to the child `go build -buildmode=plugin`: `-trimpath`, `-tags` (e.g. `netgo,osusergo`), and `CGO_ENABLED` / `GOARM64` / `GOAMD64` env. The child build must inherit these so stdlib package hashes match the host: a release host (built with `-trimpath -tags netgo,osusergo`) and a plugin built bare hash stdlib packages differently, so dlopen rejects with `plugin was built with a different version of package internal/goarch`. The build banner prints the resolved `Flags:` and `Env:` so mismatches are visible. If a plugin fails to load with `different version of package …`, check that `go version` (run from the plugin's source dir) matches the host binary's `runtime.Version()`.

**Plugin go.mod must require the SDK at the host's pseudo-version.** Under `-trimpath`, the Go compiler bakes the SDK's module version string into the position info embedded in exported declarations, which is part of the package's export hash (`go:link.pkghashbytes.github.com/BishopFox/joro/sdk`). The host's `go.mod` requires `github.com/BishopFox/joro/sdk v0.0.0-00010101000000-000000000000` (Go's canonical zero pseudo-version, auto-generated by `go mod tidy` for a local-replace dep with no real tag), so a plugin must require the same full pseudo-version — a plain `v0.0.0` produces a different export hash even with identical source and replace target, and `plugin.Open()` rejects with `different version of package github.com/BishopFox/joro/sdk`. The 5 example plugin go.mod files all use the full pseudo-version — do the same in any new plugin. (Only `-trimpath` (goreleaser) builds require the match; without it, position info uses absolute paths that happen to align, so `make build` + `--build-plugin` tolerate the mismatch.)

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

**Icons: `lucide-react`.** All UI icons come from `lucide-react` via direct named imports (`import { Filter, X } from 'lucide-react'`) — no wrapper component, no shared icons file. Size/weight per call site with `size={N}` / `strokeWidth={N}`; `color` defaults to `currentColor`, so semantic text-color classes tint icons for free (never hardcode icon colors). **Do not reintroduce emoji or Unicode/HTML-entity glyphs (🚩 ⚙ ↩ ✕ ▶ …) as icons** — use a Lucide component. Two intentional exceptions stay hand-drawn (no Lucide equivalent): the Jorōgumo spider mascot (`App.tsx`, Dead Drop nav) and the Windows/Tux/Apple OS brand marks in `NetworkGraph.tsx`'s `osIcon`. Icons rendered inside the graph's SVG coordinate space (`NetworkGraph.tsx` `osIcon`/`serverIcon`) use a nested `<svg x= y= width= height=>` viewport rather than a bare Lucide element. Typographic separators (`&bull;`, `&middot;`) are text, not icons — leave them.

---

## API Reference

All under `/api/v1/`. Request/response shapes are JSON unless noted. WebSocket events stream from `/ws`.

**History & intercept**
- `GET/DELETE /requests`, `GET /requests/:id` — paginated history with filters; raw bytes base64. Filters: `host`, `method`, `status`, `search` (URL substring), `exclude`+`extMode` (file extensions), `contentType`, `scope_only`, and `content`+`contentMode` (`include`/`exclude`) +`contentRegex` (`true`) — matches a string (case-insensitive) or regex against the **raw request + response bytes**.
  - `method` — comma-separated, case-insensitive, OR'd: `method=GET,POST`.
  - `status` — comma-separated expression OR'ing classes (`4xx`), exact codes (`403`), inclusive ranges (`500-599`), and `none` (no response captured, `StatusCode == 0`): `status=4xx,5xx,403,500-599`. A bare `status=200` still works. Unparsable tokens are skipped, and an expression with no parsable token means no filter (so a half-typed value degrades rather than blanking the table). `status=0` means `none`, **not** "any". Parser: `parseStatusFilter` in `internal/proxy/statusfilter.go`.
  - Live-streamed rows honor `method`, `status`, and `exclude`+`extMode` client-side (`requestStore.addItem`/`addItems` → `matchesLiveFilter`). `host`, `search`, `contentType`, `content*`, and `scope_only` are server-side only (raw bytes and scope rules aren't in the WS summary), so those bypass live rows until reload.
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

**Detect (passive vulnerability detection)**
- `GET /detect` — `{enabled, config, summary{total,bySeverity,byCategory,falsePositives,skippedEncoded,skippedBinary,scanned}, scan{…}, cursor, ruleCount, activeRules}`
- `PUT /detect/enabled` — `{enabled}`; `GET/PUT /detect/config` (PUT takes a **partial** patch; pointer fields, so any subset)
- `GET /detect/findings` — `?severity=&minSeverity=&category=&ruleId=&host=&search=&confidence=&fp=true|false|all&includeDisabled=&sort=severity|lastSeen|firstSeen|count|host|rule&dir=&offset=&limit=` → `{items,total,offset,limit}` (`limit=0` = all).
  **`severity` overrides `minSeverity`** rather than combining with it, and the endpoint applies no default of its own. `minSeverity` is a supported param but the UI never sends it: the findings view carries an explicit `severity` CSV (the set of visible bands, omitted entirely to mean "all"), so the two can't interact.
- `GET /detect/findings/{id}` — `{finding, notes, occurrences[{…, requestPresent}], rule}`; `PUT /detect/findings/{id}` — `{falsePositive?, notes?, severity?}`
- `DELETE /detect/findings/{id}`, `DELETE /detect/findings?fp=true` (only false-positive-marked)
- `GET /detect/rules` — `?category=&severity=&builtin=&enabled=&search=` → `{rules[] (each with findingCount), builtinCount, userCount, activeCount, categories, postFilters}`
- `POST /detect/rules` (201; `kind` must be `regex`), **`PUT /detect/rules/{id}`**, `DELETE /detect/rules/{id}` — both 403 on a built-in
- `PUT /detect/rules/{id}/enabled` — `{enabled}`; `PUT /detect/rules/{id}/severity` — `{severity}`; `POST /detect/rules/{id}/reset` — both allowed on built-ins (they change the operator's view, not the rule)
- `POST /detect/rules/test` — `{pattern, sample|sampleB64, captureGroup?, minEntropy?, minLength?}` → `{valid, error?, groups, matches[{match,redacted,offset,length,entropy,passes}], truncated}`
- `POST /detect/scan` — `{scope:"all"|"host", host?, purge?}` → 202 status (409 if already running); `GET /detect/scan`; `POST /detect/scan/cancel`

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
- `GET /system/healthcheck` — `{proxyPort, uiPort, bindAddr, caPresent, browserAvailable, browserName, requestCount, activeProject}` (first-run wizard poll)
- `GET /browser/status` — `{available, browser}`; `POST /browser/launch` — `{url?}` → `{status, browser, profile}`; `POST /browser/clear-cookies` → `{status, profile}` (clears only the active project's testing-browser profile cookies) (managed testing browser)

**Callbacks (listener mode)**
- `GET/PUT /callbacks/config` — `{domain, responseIp}`
- `GET/POST /callbacks/tokens`, `DELETE /callbacks/tokens/{id}` (cascade)
- `GET/DELETE /callbacks/interactions?token_id=`

**Sliver C2**
- `GET /sliver/status`, `POST /sliver/{connect,disconnect}`, `GET /sliver/sessions`
- `POST /sliver/execute` — `{sessionId, command, args}`
- `POST /sliver/command` — `{input}` → `{output, error, downloadId?, filename?}` (text command dispatcher)
- `GET /sliver/download/{id}` (60s TTL cache), `POST /sliver/upload` (multipart)

**Mythic C2**
- `GET /mythic/status`, `POST /mythic/{connect,disconnect}` — connect `{url, username?, password?, apiToken?}` (JWT via `POST /auth`, or `apitoken` header)
- `GET /mythic/callbacks` — active callbacks (agent instances)
- `POST /mythic/command` — `{input}` → `{output, error, downloadId?, filename?, callbackChanged?, callbackId?, callbackName?, disconnected?}` (REPL: `callbacks`/`use <id>`/`background`/`tasks`/`download`/`help`, else issues the line as a task to the active callback)
- `GET /mythic/download/{id}` (60s TTL cache), `POST /mythic/upload` (multipart)

**Team server** (auth: `Authorization: Bearer <token>` + `X-Joro-Nickname`)
- `GET/POST /team/chat`, `GET /team/users` (returns `[{nickname, status, project}]`), `POST /team/nickname` (`{oldNickname, newNickname}`), `POST /team/presence` (`{status, project}` — sets the caller's presence metadata; `project` is the active project config name)
- `GET /team/notes/hosts`, `GET/POST /team/notes`, `PUT /team/notes/{id}` (edit content), `DELETE /team/notes/{id}` — **PUT/DELETE are author-only** (soft ownership: 403 if `X-Joro-Nickname` ≠ note author). Local notes mirror this with `PUT /notes/{id}` (no ownership check — single operator). An **empty `host`** on create/list is the host-less "General" bucket (both team + local notes); the UI pins a **General** entry atop the Hosts list.
- `GET/POST /team/flagged`, `GET /team/flagged/{id}`, `DELETE /team/flagged/{id}` — shared flagged requests; POST body `{host, method, url, status, reqRaw b64, respRaw b64, note}` stores the artifact **and** posts a referencing chat message; list returns summaries (no raw bytes); get-one returns raw `reqRaw`/`respRaw` base64 + `truncated`
- `GET/POST /team/configs`, `GET /team/configs/{id}`, `DELETE /team/configs/{id}` — published (shared) project configs; POST `{name, project, config}` where `config` is base64(gzipped `projectConfigFile`) built by the proxy's `GET /configs/export` and `project` is the active project config name; list omits the blob; get-one returns it. The teamserver treats `config` as opaque. (Wire/JSON key is `project`; the SQLite column stays `project_id` — no migration.)
- `POST /team/collab`, `GET /team/collab/{id}`, `POST /team/collab/{id}/accept` — collaboration requests; POST `{project, note, config}` where `config` is a JSON 3-field bundle (scope/M&R/customdata); posts a `refType:"collab"` chat chip
- (proxy-local, not team) `GET /api/v1/configs/export` (`{config}`), `POST /api/v1/configs/import` `{name, config}` (writes a **new** local project + loads it, preserving the importer's nickname, 409 on name collision), `POST /api/v1/configs/apply-shared` `{config, mode: replace|merge}` (applies scope/M&R/customdata to live state only)

**Projects** (proxy mode; project = a saved `~/.joro/configs/project/<name>.joro` snapshot)
- `GET /api/v1/configs/project` → `{active, configs[], projects[]}` where each `ProjectMeta` is `{name, savedAt, sizeBytes, requestCount, noteCount, findingCount, autoSave, saveHistory, active}` (size/savedAt from `os.Stat`; counts/prefs from the `<name>.meta.json` sidecar, backfilled once from the `.joro` for legacy files)
- `POST /api/v1/configs/project` `{name}` (save/snapshot active), `PUT /api/v1/configs/project/{name}` (load), `DELETE /api/v1/configs/project/{name}` (also removes the sidecar)
- `POST /api/v1/configs/project/new` `{name, empty, action?: save|discard, saveScratchAs?}` — creates a **new** project (409 on collision): `empty:false` snapshots the current session under the name; `empty:true` saves the outgoing session (like a switch) then `resetLiveProjectState()` (fresh baseline: no rules, default noise, empty history/notes/highlights; team settings kept) before saving
- `POST /api/v1/configs/project/switch` `{name, action?: save|discard, saveScratchAs?}` — saves the outgoing project (respecting its `autoSave` pref, or `action`), then loads `name`; returns `applyProjectConfig`'s map + optional `{autoSaved}`
- `POST /api/v1/configs/project/prefs` `{name, autoSave?, saveHistory?}` — updates the sidecar only (no `.joro` decompress)

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
team.chat                 { id, author, text, refId?, createdAt }
team.note                 { id, host, content, author, createdAt, updatedAt }   (fires on create + edit)
team.note.deleted         { id }
team.flagged              { id, host, method, url, status, truncated, note, author, createdAt }
team.flagged.deleted      { id }
team.config               { id, name, projectId, author, createdAt }
team.config.deleted       { id }
team.collab.request       { id, requestor, projectId, note, status, createdAt }
team.collab.accepted      { id, acceptedBy }
team.presence             { users: [{ nickname, status, projectId }] }  (status online|away|dnd; appear-offline omitted; projectId "" unless shared)
team.nickname_changed     { oldNickname, newNickname }
team.relay                 { state: connecting|connected|disconnected|idle, error, httpStatus }  (proxy→teamserver relay health; deduped by state, pushed to each client on connect)
fuzzer.started            { campaignId, total }
fuzzer.result             { campaignId, result: { index, payload, payloads?, statusCode, size, words, lines, durationMs, url } }
fuzzer.complete           { campaignId, status, completed, errors }
detect.finding            { finding: FindingSummary, isNew }   (sent NON-BLOCKING, so droppable; suppressed during a rescan)
detect.summary            { total, bySeverity, byCategory, falsePositives, skippedEncoded, skippedBinary, scanned }
detect.scan.started       { jobId, kind, total }
detect.scan.progress      { jobId, scanned, total, findingsNew }   (throttled ~2/s)
detect.scan.complete      { jobId, status, scanned, findingsNew, purged, durationMs }
detect.rules.changed      { builtinCount, userCount, activeCount }
detect.findings.cleared   { deleted }
manipulate.ws.frame       { sessionId, direction: sent|received, opcode, payload (b64), isText, size, ts }
manipulate.ws.closed      { sessionId, reason }
mythic.event              { eventType: callback-new, callback: { id, display_id, user, host, os, architecture, ip, payload_type } }
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
- **Managed testing browser (`internal/browser`, proxy mode only).** `POST /browser/launch` starts an installed Chromium-family browser (`browser.Find()` precedence Chrome→Chromium→Edge→Brave; macOS app-bundle paths, Linux `exec.LookPath`+absolute fallbacks, Windows `%ProgramFiles%`/`%LocalAppData%`; no registry lookup, no new deps) with `--proxy-server=<bind>:<proxyPort>`, `--proxy-bypass-list=<-loopback>`, `--user-data-dir=~/.joro/browser-profiles/<activeProjectConfig|default>/`, and `--ignore-certificate-errors-spki-list=<fp>` where `fp = base64(sha256(ca.Cert.RawSubjectPublicKeyInfo))` (`browser.SPKIFingerprint`). The SPKI flag is only honored when `--user-data-dir` is also set. Profile dir is keyed on the active project (`sanitizeProfileKey`) so cookies never cross projects. Named-project launches are `Start()`+`Process.Release()` (detached, persistent); with **no project loaded** the profile is `default` and **ephemeral** — `LaunchOptions.WipeOnExit` makes `Launch` keep the `*Cmd`, `cmd.Wait()` for the browser to exit, then `os.RemoveAll` the profile, guarded by `profileInUse` (skips the wipe if a Chromium singleton lock — `SingletonLock`/`lockfile` — is still present, so a second concurrent launch can't delete a live session). `--test-type` suppresses Chrome's unsupported-command-line-flag infobar (the SPKI switch is on Chrome's bad-flags list); it does not alter cert validation. The presented TLS chain includes the CA cert (`cert.Certificate = append(..., ca.Cert.Raw)` in `leaf.go`) so the CA's SPKI is actually in the chain the browser sees — without it the pin matches nothing and every site errors. The optional landing URL is the last arg (Chrome reads the first non-switch arg as a URL) and persists in localStorage (`joro-testbrowser-url`, `web/src/lib/browserPrefs.ts`), shared by the Settings **Testing Browser** card and the health-check wizard. `POST /browser/clear-cookies` → `browser.ClearCookies` deletes the cookie DBs (`Default/Network/Cookies*`, legacy `Default/Cookies*`) from the active project's profile only — other site data is kept; the browser must be closed for it to take effect (Chrome holds the DB open and rewrites on exit). `browserProfile()` (`handlers_browser.go`) is the shared key/dir helper for launch + clear-cookies. (No CLI way to force Chrome's UI theme dark on macOS, so no color-scheme control.) No OS trust-store install — traffic routes through the proxy so M&R/Custom Data/scope/intercept/SOCKS-upstream apply unchanged; **do not add a browser-level SOCKS/direct-connect flag** (would bypass the proxy). `browser.Find()` returns false on hosts with none installed → `/browser/launch` 400s cleanly. Windows main binary supports this (unlike plugins). `GET /system/healthcheck` (proxy `Store.Count()` + `browser.Find()`) backs the first-run wizard (`web/src/components/HealthCheck.tsx`, embedded in `Setup.tsx`'s local flow and a Settings CA-card modal).
- **`web/dist/` embedded** via `//go:embed dist`. Populated by `npm run build` before Go compiles — `make build` runs the frontend first, and the goreleaser `before:` hook does the same. Bare `go build ./...` requires `npm run build` to have run.
- **Noise filter is separate from scope.** Silently tunnels common browser background traffic (captive portal, telemetry, OCSP, safe browsing) without capture. Enabled by default. Checked **before** scope — noisy hosts never MITM'd regardless of scope rules.
- **Two-level scope filtering.** L1 (CONNECT): host pattern only — out-of-scope hosts tunneled raw without MITM. L2 (request): host + method + path after TLS termination — out-of-scope requests forwarded without capture/intercept. Disabled by default; enabled with no rules blocks everything (safe default). Exclude rules override include rules.
- **History/Site Map method + status filters are multi-value, and shared between the two pages.** `web/src/lib/requestFilters.ts` is the single source for `HTTP_METHOD_OPTIONS`, `STATUS_CLASS_OPTIONS`, `buildStatusExpr` (chips + codes box → the `status` query param), `parseStatusExpr`/`matchesStatus` (a **hand-maintained mirror of `parseStatusFilter` in `internal/proxy/statusfilter.go` — keep in sync**, including its lenient skip-bad-tokens semantics: a strict mirror would blank the table mid-typing while the server still returns rows), and `matchesLiveFilter`, the client-side predicate `requestStore.addItem`/`addItems` apply to live `request.captured` rows. `matchesLiveFilter` covers **only** method/status/extension — the WS summary has no raw bytes or scope context, and mixing enforcement levels would make the row count disagree with the server's `total`. UI: `MultiSelectDropdown.tsx` (method popover) + `StatusFilter.tsx` (class chips + debounced codes box) are used by both History's filter bar and `SitemapFilterModal`; the store's `RequestFilter` and `SitemapFilter` both name the fields `methods`/`statusClasses`/`statusCodes` so the controls' patch objects drop straight into either setter. Method/status are deliberately **not** persisted to `localStorage` (unlike `exclude`/`content*`) — they're per-investigation, and History has no "filters active" badge, so a silently restored `4xx` would read as "the proxy stopped capturing". `MultiSelectDropdown`'s panel is `position: fixed` (to escape the filter bar and the site-map modal card) but **not** portaled, so click-outside is one `contains` check and a panel click inside the modal can't reach the backdrop's dismiss handler; it also `stopPropagation()`s ArrowUp/ArrowDown, since History installs a document-level row-navigation listener that only bails on `tagName === 'INPUT'`.
- **Listener mode is mutually exclusive with proxy mode.** `--listener` starts DNS + HTTP callback servers + reduced API/UI. No CA, proxy, or intercept. Data in `~/.joro/callbacks.db`.
- **Token entropy:** 12 hex chars = 48 bits. Correlated by leftmost subdomain label.
- **Callback listeners are capture-only and pure-stdlib.** DNS uses `miekg/dns`; HTTP/SMTP/FTP/LDAP use only `net`/`bufio`/`crypto/tls` (no third-party protocol libs — supply-chain risk). `internal/callback/{ftp,ldap}.go` clone the `SMTPServer` shape (struct + `Start(ctx)` + `acceptLoop` + per-conn goroutine + optional implicit-TLS via shared `*tls.Config`). **FTP** is a fake server that captures USER/PASS + path args and refuses the data channel (`PASV`/`PORT` → `502`); it never opens a second socket or completes a transfer. **LDAP** hand-rolls a minimal BER TLV reader (`readTLV`/`readRawMessage` in `ldap.go` — *not* `encoding/asn1`, which is too DER-strict) to pull the bind DN / search baseObject (where JNDI/Log4Shell payloads land), then replies with canned success `BindResponse`/`SearchResultDone` echoing the messageID. Both `handleConnection`s open with `defer recover()` (untrusted network input) and cap message/line sizes before allocating. New protocols reuse existing `Interaction` columns (`Type`/`SourceIP`/`RawRequest`/`Headers`) — **no schema change**; the frontend `Callbacks.tsx` already renders `ftp`/`ldap` badges + a generic detail view, so **no frontend change**.
- **Correlation helpers (`internal/callback/token.go`).** `Correlate` (DNS subdomain label), `CorrelateSMTP` (email local-part then subdomain), and `CorrelateAny(store, candidates...)` — scans arbitrary captured strings for `[0-9a-fA-F]{16,}` runs and looks up the first 16 chars via `FindTokenByHex`. FTP/LDAP feed their captured fields (+ transcript/hex fallback) into `CorrelateAny`. **Limitation (interactsh parity):** a token present only in the *hostname* (resolved by DNS) and not in the LDAP/FTP payload can't be correlated from the connection itself — but the DNS lookup already records it under the `dns` type.
- **Privileged ports need root/capabilities on Linux.** DNS `:53`, SMTP `:25`, HTTP `:80`, HTTPS `:443`, SMTPS `:465`, FTP `:21`, LDAP `:389`, FTPS `:990`, LDAPS `:636` are all <1024. `setcap cap_net_bind_service=+ep ./joro` or iptables redirect; or use the `--{dns,http,https,smtp,smtps,ftp,ftps,ldap,ldaps}-port` flags to pick unprivileged ports.
- **`internal/event` package** holds shared `WSEvent` to avoid proxy↔callback import cycle.
- **Upstream TLS is maximally permissive (`internal/proxy/tlsconfig.go`).** All connections to target servers use `newUpstreamTLSConfig()`: `InsecureSkipVerify` (we MITM, never validate), `MinVersion: TLS 1.0`, and an explicit `CipherSuites` list of every suite Go implements — `tls.CipherSuites()` **plus** `tls.InsecureCipherSuites()`. The explicit list is required because Go 1.22+ omits the static-RSA key-exchange suites (`TLS_RSA_WITH_AES_*`) from the default ClientHello: without them, legacy servers that only accept those suites fail the handshake with `remote error: tls: handshake failure` (at handshake, *before* cert verification, so `InsecureSkipVerify` doesn't help). Listing every suite matches curl/OpenSSL reach. **Caveat:** Go's `crypto/tls` implements no finite-field DHE (`TLS_DHE_*`) suites, so a DHE-only server stays unreachable. Used by `transport.go`, `client.go`, `sender.go` (H1 + H2), `ws_relay.go`, `ws_manipulate.go` — add new upstream dials through this helper too.
- **Match & Replace operates on raw bytes.** Splits raw dump at `\r\n\r\n`, applies header/body rules independently, then reparses. Cumulative in order. Supports `string` and `regex`. Targets: `request_header`, `request_body`, `response_header`, `response_body`, `ws_message`. **HTTP/1.1 and HTTP/2 have separate apply functions — keep them in sync.** The H1 path uses `applyRequestReplace`/`applyResponseReplace` (`internal/proxy/replace.go`); the H2 MITM path uses `applyRequestReplaceRaw`/`applyResponseReplaceRaw` (`internal/proxy/h2_mitm.go`) because h2 has no textual wire format and works on synthesized raw bytes. The two paths mirror each other and must stay in sync — e.g. `stripBlankHeaderLines` (collapses blank lines from an empty replacement and drops colon-less orphan lines left by a name-only match) wraps header-rule output in *both* `applyRequestReplace` and `applyRequestReplaceRaw`. The H2 *response* path reparses headers via `parseHeaderBlock` (a header map), so blank/orphan lines vanish there without the helper.
- **WebSocket MITM uses custom frame reader/writer** on raw `net.Conn` (not gorilla). Detected via `Upgrade: websocket`. After 101, two goroutines relay bidirectionally. Control frames forwarded immediately; data frames accumulated until FIN, match/replace applied on complete messages, forwarded as single frame. 16MB payload limit.
- **WebSocket Manipulate is a client path, not proxy interception.** `internal/proxy/ws_manipulate.go` dials per-session (TCP or TLS w/ `InsecureSkipVerify`, honoring `TransportConfig.SOCKSDialContext()`), writes raw upgrade verbatim (injects `Sec-WebSocket-Key` only if missing), parses 101 with `http.ReadResponse`, reassembles continuation frames, calls `onFrame` per complete message. `Send` writes a single FIN masked frame. Sessions in-memory only, dropped on restart/error/close. Transcript streamed via `manipulate.ws.frame`/`manipulate.ws.closed` — sent frames also broadcast so multiple UI tabs stay in sync. Match & Replace intentionally NOT applied — what you type is what goes on the wire.
- **Custom Data is purely additive.** Unlike Match & Replace (needs match pattern), Custom Data appends headers, query params, or body data to in-scope requests. Applied after Match & Replace. UI in "Customize Requests" tab.
- **Fuzzer:** producer-consumer goroutine pool, 1-100 threads, rate limiting. Reuses `proxy.TransportConfig.Transport()` (SOCKS, HTTP/2, keep-alive). Results streamed via `fuzzer.result` with RAF batching client-side. Response bodies NOT stored — only metrics (status, size, words, lines, duration). Campaigns in memory (max 50, oldest completed evicted). Single (`FUZZ`) or multi-position (`FUZZ1`, `FUZZ2`, ...). Multi-position attack modes: **Spray** (same payload all positions), **Split** (parallel iteration), **Yolo** (cartesian product, max 10M). Detection regex `FUZZ(\d+)` with fallback to `FUZZ`. Replaced longest-label-first (e.g. `FUZZ10` before `FUZZ1`). Matchers (whitelist) / filters (blacklist) on status, size, words, lines, regex. Content-Length auto-update toggled by `updateContentLength`.
- **Passive detection pulls from the capture store; it is never called from the request path.** `internal/detect` runs the rule library over `proxy.CapturedRequest` records. A 250 ms cursor loop (`Scanner.Run`, started by `StartDetectLoop` from `runProxyMode`, alongside `StartAutoSaveLoop`) advances a `Store.LastSeq()` watermark via `Store.SinceSeq(seq, limit)`. **Not a hook at the six `store.Add` sites** — that would run detection on the goroutine serving the browser. Pulling also makes rescan the same code path with a different starting cursor. A `wake chan struct{}` (cap 1, non-blocking send) is the coalescing doorbell for an immediate pass.
  - **`Finding.ID` IS the dedupe identity**: `hex(sha256(ruleID ‖ host ‖ groupDim))[:32]`, containing no request ID, timestamp, or seq. Rescanning reproduces byte-identical IDs, so rescan is idempotent, the frontend live-merge is a plain map upsert, and findings reload with no ID remapping. `groupDim` is **per-rule** via `Rule.GroupBy`: `host` (headers/cookies/fingerprints), `url` (panels, listings, interesting files), `evidence` (secrets/PII — one finding per distinct value, hashing the *raw* match so two secrets sharing a prefix never collide and the key never carries the secret).
  - **Every finding funnels through `Store.Upsert`**, which increments `Count` only for an unseen `requestID:part:offset` (`occSeen`, capped at 512) — without that check a rescan doubles every count. Triage (`FalsePositive`, `Notes`, severity override) is preserved across upsert, and **rescan never clears first**.
  - **Three check kinds, one output path.** Declarative regex rules (the only kind operators may create), named Go **post-filters** (`Rule.PostFilters` → `postfilters.go`: `luhn`, `iban97`, `ssn`, `denylist`, `notVersionString`, `notHTML`, …), and built-in **analyzers** (`Kind: "analyzer"`) for absence/relational logic a regex cannot express. Analyzers are rules whose behavior is a func looked up by ID, so they inherit toggling, severity override, and grouping. All converge on `Engine.newFinding`, so redaction and truncation cannot be bypassed.
  - **Patterns are RE2: no lookahead, no lookbehind, no backreferences.** Negative conditions belong in a post-filter. RE2 also caps explicit repeat counts at **1000**, and Go's `(?m)$` matches only immediately before `\n` — so a class excluding `\r` can never reach `$` on a CRLF-framed header line (header patterns end at the character class, with no anchor). `Engine.applyRegexRule` trims the captured value, since a stray `\r` would land in both the evidence and the grouping hash.
  - **`Rule.Literal` prescreen**: a case-folded `bytes.Contains` before the regex, which is what makes ~167 rules per response affordable. A wrong `Literal` **silently disables the rule** (`TestBuiltinLiteralsAreConsistent`). `builtinRules()` is a **function**, not a package var, so nothing can alias the shipped table; **every shipped rule is enabled** (no present-but-disabled tier; `TestNoBuiltinShipsDisabled`), so operator changes are a `disabled` set plus a `severityOverride` map, and `PUT`/`DELETE` on a built-in returns 403.
  - **Info findings are hidden by default, not disabled, and severity visibility is one field.** 88 of the 167 rules are Info, so `emptyDetectFilter` (`web/src/stores/detectStore.ts`) defaults `severities` to the four non-Info bands; the rules still run and their findings are still deduplicated, counted in `summary.bySeverity`, and persisted. `DetectFilter.severities` is the **visible set**, and an **empty array means no severity filter at all** — the same meaning `MultiSelectDropdown`'s "Any"/Clear and an absent `severity` param carry. There is **no separate "show info" control** and the frontend does not use `minSeverity`. The Severity dropdown and the count-bar chips write that one field; a chip **reverses one band** rather than isolating it, so `toggleSeverityChip` materializes `SEVERITY_ORDER` before subtracting. Turning off the last visible chip lands on empty and reveals everything. The default is not persisted. While a band is hidden the chips sum higher than the table's total.
  - **Evidence offsets are absolute within the rendered document, and redaction is a display control.** `Finding.EvidenceOffset` is an offset into the raw request/response the UI renders — named by `EvidencePart` — not into the buffer the rule matched against, with `-1` meaning no faithful mapping exists (a decompressed body, or a URL match). `Message.absoluteOffset` is the single translation point. `EvidenceLength` is the length of the *matched region*, which for an analyzer is not `len(Evidence)` — that field holds a synthesized description. `TestEvidenceOffsetLandsOnTheMatch` asserts the round trip (`respRaw[off:off+len] == match`). **A byte offset is not a CodeMirror document position**: `EditorState.create` splits the doc on `/\r\n?|\n/` and rejoins with `\n`, so every CRLF collapses to one character and an HTTP body offset is short by one per header line. `byteOffsetToPos` (`web/src/pages/Detect.tsx`) subtracts the preceding CRLFs; a lone `\r` costs nothing, since it is also a split point but becomes one `\n`. The plugin then **verifies** the translated range against the finding's own evidence and falls back to a text search when it does not match; verification is skipped for analyzers, whose evidence is a description rather than a slice. As on the server in `Store.Upsert`, `evidenceOffset`/`evidenceLength`/`evidencePart` are **one value** and `detectStore.upsertFindings` must move them together, or a host-grouped merge points a stale length at a fresh offset. `Finding.RawEvidence` stores the unmasked value for the 48 rules that redact and is persisted in the project file: **redaction guards against shoulder-surfing and screen sharing, not data at rest**. `Finding.Evidence` keeps the mask, which is what the findings table renders; the detail pane starts masked on every selection and the eye toggle reveals per finding.
  - **Severity follows a fixed rubric, pinned by `TestSeverityRubric`.** Info = not exploitable on its own (exposed panels, missing headers, information disclosure, analytics keys, identifiers that are not credentials); Low = an exposed config file; Medium = the catch-all; High = account credentials, sensitive API keys, DB connection strings, low-level PII; Critical = high-grade PII (national ID or payment card) or severe compromise alone (RCE, auth bypass, a served DB dump). **Every credential is High and none is Critical**, and a rule that merely detects a *surface* is Info. Critical is a literal 15-ID allow-list in the test, which also asserts `Info >= Critical * 3` and that fewer than half the library sits at High or above. Severity is orthogonal to confidence, and both are operator-overridable per rule and per finding.
  - **Bodies are not reliably plaintext.** `transport.go` sets `DisableCompression`, so Go neither requests gzip nor decodes it, `stripHopHeaders` leaves `Content-Encoding`, and the h2 path passes `Decompress: false` — so `parse.go` decompresses via the exported `proxy.TryDecompress`. Brotli/zstd are undecodable without a new dep, so those bodies are marked unscannable and **counted** (`skippedEncoded`) rather than silently skipped. `.js`/`.css` are **not** in `SkipExtensions` — the inverse of History's default exclude list.
  - **Content-type gating is a blacklist for data rules, a whitelist for format rules.** `Rule.ExcludeContentTypes` is checked before `ContentTypes` and wins outright. The seven ungated PII rules exclude `ctCSS` rather than whitelisting the formats that may carry PII, so they stay live everywhere else. **JavaScript is never excluded, and there is no `ctJS` constant**; `TestNoRuleExcludesJavaScript` pins it. `contentTypeKeyword` already returned `"css"`/`"js"`, so this added no classifier logic.
  - **Cursor resets are load-bearing.** `Store.Clear()` zeroes `nextSeq` and `LoadItems()` rewrites it, so a stale high cursor means `SinceSeq` returns nothing and **detection silently stops for the session with no error**. Reset at all four sites: `handleClearRequests`, `resetLiveProjectState` (→ 0, via `resetDetectLiveState`), and `applyProjectConfig` (→ `store.LastSeq()`, **not** 0, so restored history isn't re-reported). `SetMaxSize` needs nothing.
  - **Findings persist in the project file** (schema **v5**), gated on `Config.PersistFindings` (default on), capped at 2,000 highest-severity-first with all triaged findings always kept: false-positive marks and notes cannot be recomputed, and "recompute from `RequestHistory`" fails whenever `saveHistory` is off. `liveStateSignature` includes the findings store's `atomic.Uint64` **revision counter**, since an FP toggle or note edit changes no count. Custom detect **rules** join `sharedConfigPayload`; **findings do not** (per-operator triage, and evidence can reference live secrets).
- **Proxy-mode API enforces same-origin requests** (`internal/api/originguard.go`). `originGuard` rejects state-changing requests (and the `/ws` upgrade) unless `Sec-Fetch-Site` is `same-origin`/`none` and any `Origin` matches the host, plus a loopback/`--bind` `Host` allowlist. No `Access-Control-Allow-Origin` header is set (the SPA and plugin iframes are same-origin; the proxy→teamserver path is a non-browser Go client). Non-browser local tooling (no `Sec-Fetch-Site`/`Origin`) is allowed. The Host whitelist can be extended with `--allowed-host` (comma-separated or repeatable, hostname-only comparison) for setups that reach the loopback UI under a non-loopback Host, such as an SSH tunnel entry address. This only relaxes the Host check; the same-origin CSRF check is untouched. Listener/team-server mode uses `team.AuthMiddleware`'s bearer token instead (no origin guard).
- **Sliver C2 uses custom protowire encoding** to avoid the massive Sliver dep tree. `internal/sliver/`: `wire.go` (hand-encoded proto), `client.go` (gRPC), `commands.go` (text command dispatcher). Binary downloads/screenshots cached server-side, 60s TTL. `POST /sliver/command` is the main interface — `{input}` → `{output, error, downloadId?, filename?}`. Active session tracked in `Client.activeSessionID`.
- **Mythic C2 is a built-in exec provider mirroring Sliver, over plain HTTP + GraphQL (no new deps).** Third sub-tab on the Execute page alongside Web Shell + Sliver. `internal/mythic/`: `config.go` (`Config{URL, Username, Password, APIToken}`), `client.go` (`*http.Client` + GraphQL helper; auth = `POST /auth` → JWT **or** `apitoken` header, both supported; `InsecureSkipVerify` for Mythic's self-signed nginx cert — same stance as the proxy's upstream dials), `subscription.go` (Hasura graphql-ws live-callback events over `gorilla/websocket` as a *client* — reused, not a new dep — broadcast as `mythic.event`), `commands.go` (`Dispatch`/`CommandResult` REPL). Operates at the **callback** level only: lists callbacks, `use <display_id>` selects the active one, and typed lines are issued **agent-agnostically** as Mythic tasks (`createTask` mutation) with output retrieved by **polling** `WaitForTaskOutput`. `help` queries the callback's real `loadedcommands` (agent-specific), not static text. Installing agents / generating payloads are **out of scope** (server-side `mythic-cli` operations). Stateless like Sliver — connection details live only in `Client` memory, wiped on disconnect; proxy-mode only (nil in listener/teamserver). **GraphQL field names + file-transfer URLs target Mythic 3.3+ and may need reconciliation against other versions** (the connect UI shows a `Mythic 3.3+` support note; the `fileDownloadPath` const and query strings are the places to adjust). No Mythic scripting library is vendored (same "avoid the C2's dep tree" rationale as Sliver's protowire).
- **Team Server mode (`--listener --teamserver`)** extends listener mode with auth + collaboration. 32-char hex token generated at startup, printed to console. All teamserver requests (except `GET /api/v1/mode`) require `Authorization: Bearer <token>`. Nicknames via `X-Joro-Nickname`. Teamserver is API-only (no frontend). Proxy connects via `listenerUrl` and forwards team requests with `proxyToListener()`. Team data stored in `callbacks.db`. Active users tracked via WS hub client map (conn → nickname). Proxy maintains a WS relay (`ws_relay.go`) that forwards `team.*` events to the local hub. Nickname rename via `POST /api/v1/team/nickname` atomically renames in hub map and broadcasts `team.nickname_changed`, avoiding the disconnect/reconnect a full relay restart would cause; relay's cached nickname updated via `ListenerRelay.SetNickname()`. On 409 (collision), proxy rolls back the local `teamNickname` setting and surfaces the error. **Team Chat is a persisted session log.** On join the client fetches history (`GET /team/chat`, `listChatMessages({limit:200})` reversed to chronological) and `addMessage` dedupes by id so the live WS echo doesn't double up. Connect/disconnect/rename are persisted **server-side** as `author:"*"` system messages in `team_chat` (not synthesized client-side): the hub's `SetOnConnect`/`SetOnDisconnect` callbacks + `handleTeamRename` call `APIServer.postSystemChat`, which stores the message and broadcasts `team.chat`. `team.presence` drives only the active-users sidebar.
- **Flagged requests are self-contained artifacts, not history pointers.** Request history is local to each proxy instance, so a teammate on another machine can't dereference an ID into someone else's history. A flagged request therefore carries its own raw request/response bytes into the `team_flagged_requests` table on the team server. A **single** `POST /api/v1/team/flagged` both stores the artifact and creates a referencing chat message (via `CreateMessage`'s optional `refID` → new nullable `team_chat.ref_id` column), broadcasting **both** `team.flagged` (summary) and `team.chat` (chip). This keeps every UI entry point — History context menu, Manipulate "🚩 Flag" button, and the `/flag <seq>` chat slash command — to one API call. Responses are capped at **256KB** (`maxFlaggedRespBytes` in `handlers_team.go`) with a `truncated` flag surfaced in the viewer. List returns summaries without blobs; `GET /team/flagged/{id}` returns base64 `reqRaw`/`respRaw`. The `team_chat.ref_id` column is added by an idempotent `ALTER TABLE` in `MigrateDB` (swallows "duplicate column") since `CREATE TABLE IF NOT EXISTS` can't alter a pre-existing table. Frontend: `teamFlaggedStore` (fed by `team.flagged`/`team.flagged.deleted` WS events + a `listFlagged` poll in `useDashboardPolling`), a clickable chat chip and the **Flagged Requests dashboard widget** (available only in team mode, in whichever slot the operator's layout puts it), both opening `FlaggedRequestModal` (read-only CodeMirror + `ResponseRender`, with a "Send to Manipulate" button reusing `navigate('/manipulate', {state:{rawReq}})`). All flag entry points are gated on team mode (`listenerUrl` + `teamToken` + `teamNickname`).
- **Dead Drop shares requests via a portable file, no team server.** Where Flagged Requests need a live team server, the **Dead Drop** tab lets an operator stage captured requests (History context menu → "Stage for Dead Drop", on both the row menu — fetches bytes via `api.getRequest(id)` — and the detail menu — uses `selectedDetail`), reorder them by **drag-and-drop**, annotate, and export a self-contained **`.jord`** file that any Joro instance can import and view. **Entirely frontend, no backend/API changes.** `deadDropStore` (Zustand, **in-memory** — staged list is lost on reload; the exported file is the durable artifact) holds full records (base64 `reqRaw`/`respRaw` from `RequestDetail`). `lib/deaddrop.ts` serializes a `{type:"joro-deaddrop", version, exportedAt, author, title, note, items[]}` bundle: gzip via `CompressionStream` (plain-JSON fallback when absent) on export; on import it sniffs the gzip magic bytes `0x1f 0x8b` → `DecompressionStream`, else parses plain JSON (mirrors the backend `gunzipIfNeeded`). The **author** field is operator-entered on the staging screen (prefilled from `teamNickname` if set — no nickname exists in local mode). The viewer reuses `FlaggedRequestModal`, generalized with optional `title`/`byline` props (defaulted to the flag strings so `Dashboard` is unchanged). The access point is intentionally obscure — a low-profile icon in the header (with a staged-count badge), separate from the standard tabs rather than a named tab in `nav.ts`; the `/deaddrop` route still exists.
- **Operator presence carries opt-in status + active project name.** `team.presence` is `[{nickname, status, project}]` (not bare nicknames): the hub keeps a `presenceMeta` map (nickname → `{status, project}`) and `ActiveUsersDetailed()` joins it with `clients` (default `online`), **omits appear-offline** users, and feeds both `broadcastPresence()` and `GET /team/users`; operators set **status** (online/away/dnd/appear-offline) + a **Share project name** toggle (default off) from the Active Users dashboard widget (`components/dashboard/ActiveUsersWidget.tsx`; persisted in `Settings.TeamStatus`/`ShareProjectName`), which propagate via a forwarded `POST /team/presence` → `hub.SetPresenceMeta` (rebroadcasts, **never a relay reconnect**, so the session log isn't disturbed); the proxy pushes on join + on setting change, the server keeps meta across disconnects so a relay blip doesn't wipe a shared project, and `Rename` migrates the meta. The shared value is the active project config name (from the frontend `projectStore`), gated by the toggle.
  - **Presence is gated on the Team Chat widget.** An operator whose **team** dashboard layout has no `team-chat` widget announces `status: "offline"`, and `ActiveUsersDetailed()` already omits appear-offline users — so they don't appear on the roster at all. No backend change: the frontend simply sends a different status. "Displayed" means **in the active layout**, not currently mounted — the push lives in `App.tsx` and reads `layoutIncludes(layout, 'team', 'team-chat')`, so navigating to another tab doesn't flip anyone offline. The Active Users widget disables its status select and says why when this is in effect, and the Settings layout editor warns before you remove chat from the team layout.
- **Team relay connection state is surfaced to the UI, and team polls time out independently of the app.** The proxy→teamserver relay (`ListenerRelay`, `ws_relay.go`) reports transitions to the hub via `Hub.SetRelayState(state, err, httpStatus)` (states: `connecting`/`connected`/`disconnected`/`idle`), which broadcasts a **`team.relay`** WS event. Dedup lives in the hub (by `state` string) so the 1s→30s backoff loop can call freely without spamming; `run()` guards each call with a non-blocking `<-stop` check so a stale reconnect goroutine can't clobber the current one, and `Update()` sets `connecting` synchronously / calls `ClearRelayState()` (→`idle`) when stopped. On every `/ws` client connect, `ServeWS` re-broadcasts the last state (via the channel, **unconditional** — the local browser has no nickname) so a page reload mid-outage shows the truth. Frontend: `teamConnectionStore` (default `connecting`) fed by the `team.relay` case in `ws.ts` (toasts **only** on connected→disconnected); drives the App header dot color, the `NetworkGraph` widget's `connected` prop (gated on `settings.listenerUrl` so solo mode stays "connected"), and a status row in the Settings Team Server card. `req()` (`lib/api.ts`) takes an optional `timeoutMs` (`AbortController`); the listener-proxied polling GETs (chat/notes/flagged/users/callbacks/xss lists) use `TEAM_POLL_TIMEOUT` (4s) so a dead team server can't hang them for the full server-side `proxyToListener` timeout (10s; client abort cancels it via `r.Context()`) and starve the browser's ~6-connection HTTP/1.1 pool (which would delay unrelated local calls like `getSettings`). `useDashboardPolling` + Notes `fetchHosts`/`fetchNotes` also **skip** those proxied polls when state is `disconnected`. Do **not** add a global `req()` timeout — `/manipulate/send`, fuzzer, and uploads can be legitimately slow.
- **Team notes have soft ownership + in-place edit.** `PUT /api/v1/team/notes/{id}` edits content (bumps `updated_at`); both PUT and DELETE fetch the note first and 403 unless `team.NicknameFromContext` matches the note's `author` ("soft" because nickname is the only identity). The frontend (`Notes.tsx`) hides the ✎/✕ affordances on notes the current `teamNickname` doesn't own, and shows an "(edited)" marker when `updatedAt != createdAt`. Edit/delete broadcast `team.note` / `team.note.deleted`. Local notes (`internal/notes`) also expose `PUT /notes/{id}` but with **no** ownership check (single operator); their UI affordances always show.
- **The project config name is the engagement identity (no separate Project ID).** Every feature that labels an engagement (team presence, published configs, collab chips) uses the **active project config name** (`s.activeProjectConfig`). Wire/JSON key is `project`; the teamserver's `team_shared_configs`/`team_collab_requests` SQLite columns stay `project_id` (Go field `ProjectID`, JSON tag `project`) — no DB migration. Chat chips distinguish artifact kinds via `team_chat.ref_type` (`flagged`/`collab`/`config`); `CreateMessage` takes `(id, author, text, refID, refType)`. `handleLoadProjectConfig`/`handleSaveProjectConfig`/`handleSwitchProject` share `buildProjectConfig`/`applyProjectConfig`/`saveProject`/`gzipJSON`/`gunzipIfNeeded` — keep all paths on them.
- **Project browser + switcher + auto-save (Settings → Project, header dropdown).** A header `ProjectSwitcher` dropdown and the `ProjectBrowser` component (`web/src/components/ProjectBrowser.tsx`, embedded in the Settings page under the **Project** sidebar category) list/create/import/load projects, both driven by `projectStore` (Zustand). The dropdown's **Manage…** navigates to `/settings` with router state `{category:'project'}`; `Settings.tsx` reads `location.state.category` to open that sub-menu, then clears the state. `projectConfigFile` is **schema v5** (v4 added `autoSave` + `saveHistory`, both default true; v5 adds the `detect*` fields, with `detectEnabled` defaulting true; `normalizeProjectConfig` is the single place those version-gated defaults live). Each project has a `<name>.meta.json` **sidecar** (counts + prefs) — authoritative for prefs locally, so `handleSetProjectPrefs` toggles them without decompressing the `.joro`. `saveProject(name)` (shared by manual save / switch / auto-save) snapshots via `buildProjectConfig`, omitting request history when `saveHistory` is off. `StartAutoSaveLoop` (`internal/api/autosave.go`, from `runProxyMode`) ticks every 30s and saves the active project when `autoSave` is on and `liveStateSignature()` changed. Switching (`handleSwitchProject`) auto-saves the outgoing project when its `autoSave` is on, else the UI confirms Save/Discard/Cancel (also for an unnamed scratch session). New project (`NewProjectModal` → `handleNewProject`) prompts snapshot-current vs. start-empty. `activeProjectConfig` is **not** persisted across restarts. Frontend rehydration goes through `web/src/lib/applyProject.ts` (`applyProjectResp`), which fires a `joro:project-changed` window event.
- **The Dashboard is a frame over a widget catalog, with a layout per mode.** `web/src/pages/Dashboard.tsx` renders no panels of its own: it resolves the operator's stored layout into widgets and draws the chosen preset's rows above a shared, resizable bottom bar. Pieces: `lib/dashboardWidgets.tsx` (the catalog — `WidgetId`, `WidgetDef`, `WIDGETS`, availability), `lib/dashboardPresets.tsx` (`classic`/`triptych`/`grid`/`stack` + the two default layouts), `stores/dashboardLayoutStore.ts` (persistence), `lib/useDashboardPolling.ts` (the one poll loop), `stores/dashboardDataStore.ts` (what it polls), `components/DashboardPanel.tsx` (shared chrome), and `components/dashboard/*Widget.tsx`. Adding a widget = a component + one `WIDGETS` entry; nothing in Go, the layout store, or the Settings editor changes.
  - **Two layouts, swapped automatically.** `team` defaults to the pre-widget layout byte-for-byte (`classic`: network graph | recent interactions / flagged requests, over chat + active users); `local` defaults to `grid`: detected findings / recent interactions over network graph / proxy health, with both bar slots empty so the bar and its drag handle are hidden. Customization is **presets + a dropdown per slot** (Settings → Appearance → Dashboard layout) — deliberately **not** drag-and-drop and **no new npm dependency**.
  - **The bottom bar belongs to the frame, not to a preset.** Every preset shares `barMain` + `barAside`, so the resizer is written once and survives swapping chat out of it. Height is committed to the store **once on mouseup**, not per mousemove.
  - **Sanitize and resolve are separate, and only resolve drops widget ids.** `sanitize()` (the single gate for both `localStorage` and User Config data) validates the version, preset, and slot keys but **preserves unknown widget ids verbatim** — stripping them would let a downgrade silently destroy a layout built on a newer build, since the next `setSlot` persists the stripped copy. Unknown *and* unavailable ids are dropped at render instead, where the slot simply collapses and flex siblings take the space (which is how the old dashboard behaved when it hid the graph in listener mode). **The reconciled result is never written back** — same rule `hiddenTabs` follows, so a team widget survives a trip through local mode.
  - **Availability is two declarative flags, not a predicate.** `requiresProxyMode` (network graph, detect findings, proxy health — their endpoints don't exist in listener mode) and `requiresTeam` (flagged requests). Chat and active users are **not** `requiresTeam`: they degrade to a local scratchpad and a list of one. Flags rather than a closure so the Settings editor can say *why* a widget is unavailable.
  - **Polling is centralized and keyed on the resolved layout.** `needs` is the union of the `DataNeed`s of the widgets actually in the layout, computed **before** render — not from mount-time registration, which races the first tick. A widget that isn't on the dashboard costs no requests. The `teamDown` short-circuit (skip listener-proxied polls when the relay is down) lives here; do not scatter it into widgets.
  - **Persistence: `localStorage['joro-dashboard-layout']` (schema v1), plus `userConfigFile` v4.** Follows the `joro-hidden-tabs` pattern (hand-rolled `load`/`persist`, no zustand middleware). The Go side treats it as an opaque `json.RawMessage`, like `PluginStates`; **no normalizer** is needed since `userConfigFile.Version` is never read and a v3 file just decodes to `nil`. Not in the Go `Settings` struct (nothing there is cosmetic) and not in `projectConfigFile` (that is shared with teammates; this is per-operator chrome). First load seeds `barHeight` from the legacy `joro-chat-height` key.
- **Project-config settings live in Settings → Project, inline under the project table.** `web/src/components/ProjectSettings.tsx` owns the **Team Server** card, **Team Configs** panel (`TeamConfigsPanel`), and the tabbed **Filtering** card (Scope / Noise / Match&Replace / Custom Data) — all backed by `projectConfigFile`; it hydrates on mount + on `joro:project-changed`. It is rendered inline by `ProjectBrowser.tsx` below the project table (no longer a modal). `web/src/pages/Settings.tsx` is a sidebar-driven page (`CATEGORIES` array + `category` state): **Project** (the `ProjectBrowser`), **General** (user-config + machine settings: Server, Proxy, Connection, SOCKS, User Config), **Appearance**, and **Testing Browser**.
- **Feature: publish / load a shared project config (async, whole-project).** `GET /api/v1/configs/export` serializes the current live project (via `buildProjectConfig` + `gzipJSON`, the same helpers the save handler uses) to base64(gzip); the frontend publishes it to the `team_shared_configs` table on the team server (`POST /team/configs {name, project, config}`, blob opaque to the server) and it appears in the Settings **Team Configs** panel. Loading calls `POST /api/v1/configs/import`, which writes a **new** local project file and runs the shared `applyProjectConfig` — **preserving the importer's own nickname** (adopts the shared listener URL + token) and returning **409 on a name collision** rather than clobbering. This shares the full project (scope/M&R/customdata + noise, notes, highlights, history, plugin states, team settings).
- **Team chat slash commands** (all handled in `TeamChatWidget.sendMessage`, team-mode only; in solo mode they show a "connect to a team server" hint instead of posting literal text). `/flag <seq> [note]` and `/collab <note>` (above); `/slap <user>` and `/me <text>` post **IRC-style action messages** — `sendChatMessage(text, 'action')` sets `refType:"action"` (the only client-settable refType; `handleCreateChatMessage` rejects forged `flagged`/`collab`/`config`), rendered italic as `* <author> <text>` with no name-colon prefix; `/nick <name>` calls `updateSettings({teamNickname})` (reuses the rename→`renameOnTeamServer` path, surfaces 409); `/help` appends a **local-only** `author:"*"` system message (the system-message span is `whitespace-pre-wrap` so the multi-line list renders).
- **Feature: collaboration request → diff-aware swap (via chat, rules-only).** The `/collab <note>` chat slash command posts a `team_collab_requests` row carrying a **3-field bundle** (scope/M&R/customdata JSON, built by `gatherCurrentRules()`) + a `refType:"collab"` chat chip naming the active project. Clicking the chip opens `CollabSwapModal`, which diffs the incoming bundle against the operator's current rules and offers four actions: **merge / save-and-load / load-without-saving / keep-current**. Merge/replace go through `POST /api/v1/configs/apply-shared {config, mode}` → bulk setters on **scope/replace/customdata only** — the swap **never touches history, notes, highlights, team settings, or the project-file schema**. `save-and-load` first calls the existing `saveProjectConfig`; `keep-current` applies nothing. Every choice records `POST /team/collab/{id}/accept`.
- **Plugin system uses Go's `plugin` package** (.so on Linux, .dylib on macOS). **Linux and macOS only** — Go's plugin package does not support Windows or any GOOS outside Linux/Darwin/FreeBSD. `joro --build-plugin` errors immediately on Windows; release binaries on Windows still load fine but cannot use plugins. Plugin support requires the host binary to be built with `CGO_ENABLED=1`; the goreleaser config + Makefile do this via `zig cc`. Loaded at startup from `~/.joro/plugins/`. Each exports `var Plugin sdk.Plugin`. SDK in `sdk/sdk.go` as separate Go module (`replace` in go.mod). Six plugin types: `exec_provider`, `tab`, `feature`, `proxy_hook`, `dashboard` (only one active), `interact_provider`. Names match `^[a-z0-9][a-z0-9_-]*$`, can't be reserved (`api`, `ws`, `ext`, `system`). All method calls wrapped with panic recovery. Plugins get scoped data dir (`~/.joro/plugin-data/{name}/`) and scoped WS broadcast (events auto-prefixed `plugin.{name}.`). Tab/feature/dashboard plugins serve embedded UIs at `/plugin/{name}/` in iframes sandboxed with `allow-scripts allow-forms allow-same-origin`. `allow-same-origin` makes their `/api/v1/*` calls genuine same-origin requests (so they pass `originGuard` with no plugin code changes); it's safe because plugins are already trusted native code running in-process, so the iframe sandbox was never a real boundary against them. Upload/delete require restart — Plugins page has "Restart Now" button (`POST /api/v1/system/restart`, same `syscall.Exec` re-exec as updates). Proxy hooks run in load order; `OnRequest` returning nil drops a request. `ConfigField.Type` ∈ `text|password|textarea|file|checkbox`; checkboxes serialize as `"true"`/`"false"` to preserve `map[string]string` wire shape.
- **Plugin state persistence is opt-in via two SDK interfaces.** `UserStatefulPlugin` (`ExportUserState`/`ImportUserState`) — operator-scoped state riding with User Configs (API keys, personal tokens). `ProjectStatefulPlugin` (`ExportProjectState`/`ImportProjectState`) — engagement-scoped state riding with Project Configs (active sessions, instance configs). May implement either, both, or neither. State bytes are opaque — plugins own schema and migration. No autosave on shutdown, no separate on-disk state files: serialized only when user saves a User/Project Config, applied only on load. `internal/plugins/manager.go` exposes `{Export,Apply}{User,Project}States`. Config handlers in `internal/api/handlers_configs.go` embed a `pluginStates` map (name → base64 blob) in `userConfigFile` (v4) and `projectConfigFile` (v5), and ghost-preserve blobs for plugins not installed locally via `APIServer.pendingUserPluginStates` / `pendingProjectPluginStates`, so a load→save round-trip never drops state for missing plugins. Load responses include `unknownPluginStates: []` shown in Settings.
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

Limited automated coverage (`go test ./...` — `internal/callback/listeners_test.go`, `internal/proxy/statusfilter_test.go`, `internal/proxy/store_test.go`, and the `internal/detect` suite, where `parse_test.go` pins the assumptions about raw capture bytes); otherwise manual verification:

1. `go build ./...` compiles cleanly, `go test ./...` passes
2. `./joro` prints `Proxy listening on :8080` and `UI available at http://localhost:9090`
3. Browser proxy → `localhost:8080`; import `~/.joro/ca.crt`
4. Browse HTTPS site; requests appear in History
5. History filters: pick two methods from the Method dropdown, toggle a status class, type `403,500-599` in the codes box — table narrows, and live rows that don't match stop appearing
6. Enable Intercept; next request pauses; edit and forward
7. Manipulate (HTTP): paste raw, send, verify response + timing
8. Manipulate (WS): connect to `wss://echo.websocket.events/`, send text/binary/ping, verify echo, disconnect
9. Generate PHP/ASHX shell, verify auth key + content
10. Execute: enter target + shell + key, run `whoami`
11. Plugins: `./joro --build-plugin examples/plugins/hello-feature --install`, restart, verify load; upload via UI + "Restart Now" + verify
12. Dashboard layouts:
    - Team mode, fresh install → the dashboard is unchanged from before widgets existed, chat height included (seeded from the old `joro-chat-height` key).
    - Settings → Appearance → Dashboard layout: switch the preset to **Classic** → the graph beside a stacked pair, bar intact; drag the handle, reload → the height persists. Set a slot to **None** → its siblings expand, with no placeholder card. Switch preset away and back → your widget picks survive.
    - Disconnect the team server → Flagged Requests disappears and the rest holds; reconnect → it returns (proves stored ids are never rewritten). No 4s hangs in the network tab.
    - Listener mode (`./joro --listener`) → the network graph / detect / proxy health slots collapse **and their endpoints are never requested**.
    - Solo proxy → the local default (a 2×2 grid: detected findings / recent interactions over network graph / proxy health). Clicking a severity chip lands on `/detect` filtered to that band; clicking a row lands on that finding with its detail pane open.
    - Presence gating (two team-mode instances): remove **Team Chat** from operator A's team layout → A vanishes from B's Active Users list and A's own status select greys out with an explanation; add it back → A reappears. Navigating A to another tab must **not** drop them from the roster.
    - User Config round trip: customize both layouts, save a User Config, **Reset** both, load the config → both return. Hand-edit a saved config to `"version": 3` and delete `dashboardLayout` → it loads cleanly and leaves the current layout alone.
13. Detect — browse a target, then check the Detect tab within a second or so:
    - Findings stream in, sorted Critical-first; the per-severity chips in the count bar sum to the table total; revisiting a page bumps `#` **without** adding a row.
    - **Severity visibility** is one field, driven from two places. On a fresh load the Severity dropdown reads **4 selected** (not "Any" — Info is filtered out) and the Info chip is dimmed, so the chips sum higher than the table total. Click the dimmed Info chip → Info rows appear and **every other band stays**; click a bright Critical chip → Critical rows leave and everything else stays. Unchecking a band in the dropdown dims its chip and vice versa. Dropdown **Clear** → "Any" and every band shows.
    - **Positive controls** (serve a fixture containing each): `AKIAIOSFODNN7EXAMPLE`, a `-----BEGIN RSA PRIVATE KEY-----` block, a Luhn-valid PAN such as `5500005555555559`, `Set-Cookie: sessionid=…` with no `HttpOnly`, and an `<input type="password">`. Secret and PII evidence must render **redacted** (`AKIA******MPLE`) in the table and on first selection; the eye toggle beside the detail pane's Evidence heading reveals the real value. Check the highlight lands **exactly** on the match — not in the header block (offsets relative to the wrong buffer) and not a few characters to its left (byte offsets applied to a CRLF-normalized document). Use a response with many headers and a long body, where a small shift is still visible.
    - **Negative control for the content-type blacklist**: a stylesheet whose selectors fit a PII shape produces nothing, while the same string in JSON still fires, and a secret planted in a `.js` bundle is still detected.
    - **Negative controls** (must produce nothing): `YOUR_API_KEY_HERE`, the published test PAN `4111111111111111`, `XSRF-TOKEN` without `HttpOnly`, a CSP with `unsafe-inline` **plus** a nonce, and a missing HSTS header on a **plain-HTTP** response.
    - Rules sub-tab: the checkbox toggles a rule in place (no modal); clicking the row body opens `DetectRuleModal`, where Enabled and Severity sit at the top and are editable for built-ins too. Filtering the list by **Off** is empty on a fresh install.
    - Disable a rule → its findings remain but are hidden until "From disabled rules" is checked. Add a custom rule with a lookahead → 400 with a readable RE2 error. With a dirty draft, backdrop click and Escape are ignored (use Cancel).
    - Clear findings, then **Rescan** → the same findings return with **identical counts** (idempotence).
    - Save the project, switch away and back → findings, FP marks, notes, custom rules, and disabled-rule state all survive; the project browser shows the finding count.
    - Click **Clear History**, browse again → new findings still appear (guards the stale cursor).
    - `go test -race ./internal/detect/...` stays clean.
