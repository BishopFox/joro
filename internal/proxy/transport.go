package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// TransportConfig manages HTTP transport settings (HTTP/2, keep-alive, SOCKS)
// and rebuilds the shared transport when settings change.
type TransportConfig struct {
	mu           sync.RWMutex
	http2Enabled bool
	keepAlive    bool

	socksHost     string
	socksPort     int
	socksUsername string
	socksPassword string
	socksDNS      bool

	transport *http.Transport
}

// NewTransportConfig creates a TransportConfig with defaults: HTTP/2 enabled, keep-alive disabled.
func NewTransportConfig() *TransportConfig {
	tc := &TransportConfig{
		http2Enabled: true,
		keepAlive:    false,
	}
	tc.transport = tc.buildTransport()
	return tc
}

// Transport returns the current cached transport.
func (tc *TransportConfig) Transport() *http.Transport {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.transport
}

// HTTP2 returns whether HTTP/2 upstream is enabled.
func (tc *TransportConfig) HTTP2() bool {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.http2Enabled
}

// KeepAlive returns whether keep-alive is enabled.
func (tc *TransportConfig) KeepAlive() bool {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.keepAlive
}

// SOCKS returns the current SOCKS proxy settings.
func (tc *TransportConfig) SOCKS() (host string, port int, username, password string, dns bool) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.socksHost, tc.socksPort, tc.socksUsername, tc.socksPassword, tc.socksDNS
}

// SetHTTP2 enables or disables HTTP/2 upstream negotiation.
func (tc *TransportConfig) SetHTTP2(enabled bool) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.http2Enabled == enabled {
		return
	}
	tc.http2Enabled = enabled
	tc.transport = tc.buildTransport()
}

// SetKeepAlive enables or disables TCP connection reuse.
func (tc *TransportConfig) SetKeepAlive(enabled bool) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.keepAlive == enabled {
		return
	}
	tc.keepAlive = enabled
	tc.transport = tc.buildTransport()
}

// SetSOCKS configures an upstream SOCKS5 proxy. Pass empty host to disable.
func (tc *TransportConfig) SetSOCKS(host string, port int, username, password string, dns bool) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.socksHost = host
	tc.socksPort = port
	tc.socksUsername = username
	tc.socksPassword = password
	tc.socksDNS = dns
	tc.transport = tc.buildTransport()
}

// SOCKSDialContext returns a DialContext function that routes through the SOCKS proxy,
// or nil if no SOCKS proxy is configured. Used by tunnel() and NewHTTPClient().
func (tc *TransportConfig) SOCKSDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	if tc.socksHost == "" {
		return nil
	}
	return tc.buildSOCKSDialContext()
}

// buildSOCKSDialContext creates a SOCKS5 dial function. Caller must hold at least RLock.
func (tc *TransportConfig) buildSOCKSDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", tc.socksHost, tc.socksPort)
	var auth *proxy.Auth
	if tc.socksUsername != "" {
		auth = &proxy.Auth{User: tc.socksUsername, Password: tc.socksPassword}
	}

	if tc.socksDNS {
		// Let the SOCKS proxy resolve DNS - dial with hostname.
		dialer, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
		if err != nil {
			return nil
		}
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			return cd.DialContext
		}
		return func(ctx context.Context, network, a string) (net.Conn, error) {
			return dialer.Dial(network, a)
		}
	}

	// Resolve DNS locally, then dial through SOCKS with the IP.
	dialer, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
	if err != nil {
		return nil
	}
	return func(ctx context.Context, network, a string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(a)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			return nil, err
		}
		resolved := net.JoinHostPort(ips[0], port)
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, network, resolved)
		}
		return dialer.Dial(network, resolved)
	}
}

func (tc *TransportConfig) buildTransport() *http.Transport {
	t := &http.Transport{
		ForceAttemptHTTP2:     tc.http2Enabled,
		DisableKeepAlives:     !tc.keepAlive,
		DisableCompression:    true,
		TLSClientConfig:       newUpstreamTLSConfig("", nil),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}
	if tc.socksHost != "" {
		t.DialContext = tc.buildSOCKSDialContext()
	}
	return t
}
