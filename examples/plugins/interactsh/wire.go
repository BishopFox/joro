// Stdlib-only interactsh wire protocol: /register, /poll, /deregister,
// RSA-OAEP-SHA256 key exchange, AES-256-CTR message decryption, per-server
// http.Client with opt-in TLS skip-verify for self-signed deployments.
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// The interactsh server recognises a subdomain label as a correlation ID
	// only when its length is exactly correlationIDLen+nonceLen and the label
	// is fully alphanumeric (pkg/server/util.go:isCorrelationID upstream).
	// Our payload URLs therefore embed both parts: <corrID><nonce>.<host>.
	correlationIDLen = 20
	nonceLen         = 13
	pollInterval     = 5 * time.Second
	requestTimeout   = 15 * time.Second
)

// lowercase alphanumeric — any prefix match works server-side.
const idAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// registerRequest matches interactsh's server.RegisterRequest JSON shape.
type registerRequest struct {
	PublicKey     string `json:"public-key"`
	SecretKey     string `json:"secret-key"`
	CorrelationID string `json:"correlation-id"`
}

// deregisterRequest matches interactsh's server.DeregisterRequest JSON shape.
type deregisterRequest struct {
	CorrelationID string `json:"correlation-id"`
	SecretKey     string `json:"secret-key"`
}

// pollResponse matches interactsh's server.PollResponse JSON shape.
// Only the fields we use are declared; unknown fields are ignored.
type pollResponse struct {
	Data   []string `json:"data"`
	Extra  []string `json:"extra"`
	AESKey string   `json:"aes_key"`
}

// serverInteraction matches interactsh's server.Interaction JSON shape.
type serverInteraction struct {
	Protocol      string    `json:"protocol"`
	UniqueID      string    `json:"unique-id"`
	FullID        string    `json:"full-id"`
	QType         string    `json:"q-type,omitempty"`
	RawRequest    string    `json:"raw-request,omitempty"`
	RemoteAddress string    `json:"remote-address"`
	Timestamp     time.Time `json:"timestamp"`
}

// newHTTPClient returns an http.Client scoped to one server. InsecureSkipVerify
// is opt-in per instance (off by default) — self-hosted interactsh deployments
// overwhelmingly use self-signed or internal-CA certs, so without this toggle
// the plugin is unusable for private servers.
func newHTTPClient(skipVerify bool) *http.Client {
	return &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify}, //nolint:gosec // opt-in per instance for self-signed servers
		},
	}
}

// generateID returns an n-character lowercase alphanumeric ID using crypto/rand.
func generateID(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("interactsh: read rand: " + err.Error())
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = idAlphabet[int(b)%len(idAlphabet)]
	}
	return string(out)
}

// uuidV4 returns a UUID-v4 string built from 16 random bytes using only
// crypto/rand + bit-twiddling (no third-party uuid dependency).
func uuidV4() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("interactsh: read rand: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// encodePublicKey produces the base64-encoded PEM-wrapped PKIX form of pub
// that interactsh's /register endpoint expects as the "public-key" field.
func encodePublicKey(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der})
	return base64.StdEncoding.EncodeToString(p), nil
}

// registerServer generates an RSA keypair + correlation ID + secret, performs
// the /register handshake, and returns the populated identity. On error,
// status is set to "error" with the error message.
func registerServer(ctx context.Context, srv *server) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate rsa key: %w", err)
	}
	srv.privKey = priv
	srv.correlationID = generateID(correlationIDLen)
	srv.nonce = generateID(nonceLen)
	srv.secretKey = uuidV4()

	pubEncoded, err := encodePublicKey(&priv.PublicKey)
	if err != nil {
		return err
	}
	body, err := json.Marshal(registerRequest{
		PublicKey:     pubEncoded,
		SecretKey:     srv.secretKey,
		CorrelationID: srv.correlationID,
	})
	if err != nil {
		return fmt.Errorf("marshal register: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", trimSlash(srv.serverURL)+"/register", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if srv.authToken != "" {
		req.Header.Set("Authorization", srv.authToken)
	}

	client := newHTTPClient(srv.skipVerify)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("register request: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		return errors.New("invalid auth token for interactsh server")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	// Store the payload host (leftmost-label correlation target).
	if u, err := url.Parse(srv.serverURL); err == nil {
		srv.payloadHost = u.Host
	} else {
		srv.payloadHost = srv.serverURL
	}
	return nil
}

// deregisterServer is best-effort; errors are logged but not returned.
func deregisterServer(ctx context.Context, srv *server) {
	body, err := json.Marshal(deregisterRequest{
		CorrelationID: srv.correlationID,
		SecretKey:     srv.secretKey,
	})
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, "POST", trimSlash(srv.serverURL)+"/deregister", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if srv.authToken != "" {
		req.Header.Set("Authorization", srv.authToken)
	}
	client := newHTTPClient(srv.skipVerify)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("interactsh: deregister %s: %v", srv.serverURL, err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
}

// pollOnce fetches pending interactions and invokes onInteraction for each
// decrypted server.Interaction.
func pollOnce(ctx context.Context, srv *server, onInteraction func(*serverInteraction)) error {
	u := fmt.Sprintf("%s/poll?id=%s&secret=%s",
		trimSlash(srv.serverURL),
		url.QueryEscape(srv.correlationID),
		url.QueryEscape(srv.secretKey),
	)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return err
	}
	if srv.authToken != "" {
		req.Header.Set("Authorization", srv.authToken)
	}

	client := newHTTPClient(srv.skipVerify)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("poll request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("poll failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var pr pollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return fmt.Errorf("decode poll response: %w", err)
	}

	// Encrypted entries: each is base64(IV || ciphertext) decrypted under an
	// AES key that is itself RSA-OAEP-SHA256 encrypted for our pubkey.
	if len(pr.Data) > 0 {
		aesKey, err := decryptAESKey(srv.privKey, pr.AESKey)
		if err != nil {
			return fmt.Errorf("decrypt aes key: %w", err)
		}
		for _, enc := range pr.Data {
			plain, err := decryptMessage(aesKey, enc)
			if err != nil {
				log.Printf("interactsh: decrypt data: %v", err)
				continue
			}
			var ix serverInteraction
			if err := json.Unmarshal(bytes.TrimRight(plain, " \t\r\n"), &ix); err != nil {
				log.Printf("interactsh: unmarshal interaction: %v", err)
				continue
			}
			onInteraction(&ix)
		}
	}

	// "extra" entries are plaintext strings containing interaction JSON.
	for _, raw := range pr.Extra {
		var ix serverInteraction
		if err := json.Unmarshal([]byte(raw), &ix); err != nil {
			continue
		}
		onInteraction(&ix)
	}
	return nil
}

// decryptAESKey unwraps the session AES key via RSA-OAEP-SHA256.
func decryptAESKey(priv *rsa.PrivateKey, b64Key string) ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ct, nil)
}

// decryptMessage reverses interactsh's AES-256-CTR message encoding.
// Ciphertext is base64(IV || ciphertext). IV is the first aes.BlockSize bytes.
func decryptMessage(aesKey []byte, b64 string) ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(ct) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	iv := ct[:aes.BlockSize]
	body := ct[aes.BlockSize:]
	out := make([]byte, len(body))
	cipher.NewCTR(block, iv).XORKeyStream(out, body)
	return out, nil
}

// pollLoop runs poll-every-5s against a single server until ctx is cancelled.
// Errors flip the instance status but don't abort the loop — matching the
// forgiving behaviour of the upstream client.
func pollLoop(ctx context.Context, srv *server, onInteraction func(*serverInteraction), setStatus func(string, string)) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	// One immediate poll so interactions show up without a 5s wait.
	doPoll := func() {
		if err := pollOnce(ctx, srv, onInteraction); err != nil {
			if ctx.Err() == nil {
				setStatus("error", err.Error())
			}
			return
		}
		setStatus("connected", "")
	}
	doPoll()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			doPoll()
		}
	}
}

func trimSlash(s string) string { return strings.TrimRight(s, "/") }
