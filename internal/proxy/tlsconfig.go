package proxy

import "crypto/tls"

// upstreamCipherSuites is the broadest set of TLS 1.0-1.2 cipher suites Go can
// offer: every suite crypto/tls implements, including the ones it considers
// insecure (CBC, 3DES) and the static-RSA key-exchange suites that Go 1.22+
// dropped from the default ClientHello. We advertise all of them when talking
// to upstream/target servers because pentest targets are frequently legacy or
// misconfigured boxes that only accept old suites; matching curl/OpenSSL reach
// matters far more than enforcing modern crypto on a connection we already MITM
// and never certificate-verify.
//
// Caveat: Go's crypto/tls implements no finite-field DHE (TLS_DHE_*) suites, so
// a server that offers ONLY DHE key exchange remains unreachable regardless of
// this list. TLS 1.3 suites are not configurable in Go and stay enabled.
var upstreamCipherSuites = func() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}()

// newUpstreamTLSConfig builds a tls.Config for dialing upstream/target servers:
// certificate verification disabled (we MITM and inspect, never validate), a
// TLS 1.0 floor for legacy reach, and the full cipher set above. serverName
// sets SNI (empty to omit); nextProtos sets ALPN (nil to omit).
func newUpstreamTLSConfig(serverName string, nextProtos []string) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       upstreamCipherSuites,
		NextProtos:         nextProtos,
	}
}
