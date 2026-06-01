# Security

Joro is a penetration testing tool designed to intercept, inspect, and modify HTTP/HTTPS traffic. Several patterns that would be vulnerabilities in a production application are intentional design choices here.

## Security Model

Joro is a **local security tool**, not a production service. The primary user is the pentester running it on their own machine or in a controlled lab environment. The threat model assumes the user trusts their local environment and is intentionally performing security testing against targets they are authorized to test.

## Safe Defaults

- **Proxy mode** binds to `127.0.0.1` by default. The proxy, web UI, and API are only accessible from the local machine.
- **Listener mode** (`--listener`) binds to `0.0.0.0` by default because it needs to receive DNS and HTTP callbacks from external targets. Ensure your firewall is configured appropriately.
- Use `--bind <address>` to override the default bind address in either mode. A warning is printed to stderr when binding to a non-localhost address.

## Intentional Design Tradeoffs

### TLS Certificate Verification Disabled

The proxy's upstream HTTP client sets `InsecureSkipVerify: true` to skip TLS certificate verification. This is required for MITM proxy functionality: the proxy terminates TLS with its own CA certificate and re-establishes connections to upstream servers. Without this, the proxy could not intercept traffic to servers with self-signed, expired, or otherwise invalid certificates, which is a common scenario during penetration tests.

### Cross-Origin Request Protection (Proxy Mode)

Proxy mode sets no `Access-Control-Allow-Origin` header. State-changing requests (`POST`/`PUT`/`DELETE`/`PATCH`) and the WebSocket upgrade are accepted only from same-origin contexts (validated via `Sec-Fetch-Site`/`Origin`), and the `Host` header must be loopback or the configured `--bind` address. Non-browser local tooling is unaffected.

If you bind proxy mode to a non-loopback address, the API is reachable and unauthenticated to anyone who can reach the port — use a firewall, or use listener/team-server mode for shared deployments. Listener and team-server mode require a bearer token (`Authorization: Bearer <token>`) on every request.

### Arbitrary HTTP Requests

The Manipulate feature sends user-crafted HTTP requests to arbitrary destinations. This is the core functionality of the tool for manual testing.

### WebSocket Auth Token in Query Parameter

Team server mode accepts the authentication token as a `?token=` query parameter for WebSocket connections. This is a known browser limitation: the WebSocket API does not support custom headers during the upgrade handshake. This is acceptable because WebSocket URLs are not stored in browser history, do not appear in Referer headers, and team mode is intended for use on trusted networks.

## Reporting Vulnerabilities

If you discover a security issue in Joro itself (not the intentional behaviors described above), please report it via GitHub's private [report a vulnerability feature](https://github.com/BishopFox/joro/security/advisories).
