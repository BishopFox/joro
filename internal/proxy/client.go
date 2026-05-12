package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"time"
)

// NewHTTPClient creates an http.Client that optionally routes through a proxy.
// proxyURL may be empty for no proxy. tc may be nil for sensible defaults.
func NewHTTPClient(proxyURL string, tc *TransportConfig) http.Client {
	var transport *http.Transport
	if tc != nil {
		// Clone settings from the TransportConfig but create a new transport
		// so we can safely set a proxy without mutating the shared one.
		transport = &http.Transport{
			ForceAttemptHTTP2: tc.HTTP2(),
			DisableKeepAlives: !tc.KeepAlive(),
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			DialContext:        tc.SOCKSDialContext(),
		}
	} else {
		transport = &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
	}

	if proxyURL != "" && proxyURL != "NOPROXY" {
		if u, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}

	return http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// MakeRequest performs an HTTP request using the provided client with a configurable timeout.
func MakeRequest(method, target string, timeout int64, body io.Reader, client http.Client) ([]byte, string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, "", 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", 0, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", 0, err
	}

	return bodyBytes, string(bodyBytes), resp.StatusCode, nil
}
