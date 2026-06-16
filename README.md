# Joro

![](assets/header.png)

A web exploitation framework for offensive security professionals. Intercepting proxy, blind vulnerability detection, web shell generation, C2 integration, and collaboration tools in a single binary with an embedded web UI.

> Warning: This tool is intended for authorized penetration testing and security research only. You must only use Joro against systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. Bishop Fox assumes no liability and is not responsible for any misuse or damage caused by this tool. Use responsibly.

## Features

- **Intercepting proxy** - capture, inspect, and modify HTTP/HTTPS traffic in real time
- **HTTPS MITM** - transparent TLS interception using a generated CA certificate
- **HTTP History** - searchable, filterable log of all proxied requests and responses
- **WebSocket capture** - inspect WebSocket frames alongside HTTP traffic
- **Intercept** - pause requests mid-flight, edit them in a syntax-highlighted editor, then forward or drop
- **Manipulate** - send and replay raw HTTP requests with a side-by-side response viewer
- **Site Map** - auto-generated tree of all proxied hosts, endpoints, and query parameter variants
- **Fuzzer** - multi-position HTTP fuzzer with configurable concurrency, matchers, filters, and three attack modes
- **Generate** - generate obfuscated web shells and droppers in PHP, ASP, ASPX, JSP, and CFM
- **Execute** - run commands via deployed web shells or a connected Sliver C2 teamserver
- **Listener mode** - out-of-band callback server (DNS + HTTP) for blind vulnerability detection
- **XSS Hunter** - blind XSS detection with probe payloads, screenshot capture, and DOM snapshots
- **Sliver C2** - connect to a Sliver teamserver to execute commands on active sessions and beacons
- **Transform** - encoding/decoding chains, hash generation, and JWT tampering tools
- **Team Server** - collaborative mode with shared team chat, shared notes, and active user presence
- **Notes** - per-host notes for tracking findings during engagements
- **Plugins** - extend Joro with Go plugins for custom execution backends, proxy hooks, tabs, and dashboards (Linux and macOS only - Go's plugin package does not support Windows)
- **Single binary** - the entire UI is embedded, nothing to install separately

## Installation

See the Joro wiki for [installation instructions](https://github.com/BishopFox/joro/wiki/Installation) and a [quick start guide](https://github.com/BishopFox/joro/wiki/Getting-Started).

## Help

For more information:
- Checkout the [wiki](https://github.com/BishopFox/joro/wiki)
- Review outstanding [issues](https://github.com/BishopFox/joro/issues) or [create your own](https://github.com/BishopFox/joro/issues/new/choose).
- See [CONTRIBUTING.md](https://github.com/BishopFox/joro/blob/main/CONTRIBUTING.md) for information on how to contribute.
- See [CLAUDE.md](https://github.com/BishopFox/joro/blob/main/CLAUDE.md) for detailed developer documentation.
- See [SECURITY.md](https://github.com/BishopFox/joro/blob/main/SECURITY.md) for information on reporting security issues.

### License - GPLv3

Joro is licensed under [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html), some sub-components may have separate licenses. See their respective subdirectories in this project for details.