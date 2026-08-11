package automation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type contextKey string

const tokenKey contextKey = "automation.token"

// AuthMiddleware resolves an Authorization: Bearer secret to a Token and puts it
// in the request context. It is deliberately separate from team.AuthMiddleware:
// that one compares a single process-wide token and trusts a self-asserted
// nickname, whereas this one resolves many tokens with distinct grant sets.
//
// Unlike the team middleware there is no ?token= query fallback. That exists there
// for the browser's WebSocket, which cannot set headers; an MCP client is not a
// browser, and a secret in a query string lands in proxy logs and shell history.
//
// An unknown token and an absent header produce byte-identical responses, so the
// endpoint cannot be used to confirm that a guessed secret exists. Disabled and
// expired are distinguished, which is safe because they only fire on a correct
// secret.
func AuthMiddleware(store *Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeAuthError(w, http.StatusServiceUnavailable, "automation is not configured")
			return
		}

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeAuthError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		secret := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))

		tok, err := store.Lookup(secret)
		if err != nil {
			switch {
			case errors.Is(err, ErrDisabled):
				writeAuthError(w, http.StatusForbidden, "this token is disabled")
			case errors.Is(err, ErrExpired):
				writeAuthError(w, http.StatusForbidden, "this token has expired")
			default:
				writeAuthError(w, http.StatusUnauthorized, "unauthorized")
			}
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tokenKey, tok)))
	})
}

// TokenFromContext returns the authenticated token, or nil.
func TokenFromContext(ctx context.Context) *Token {
	if t, ok := ctx.Value(tokenKey).(*Token); ok {
		return t
	}
	return nil
}

func writeAuthError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="joro"`)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}
