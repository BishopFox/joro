package team

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
)

type contextKey string

const nicknameKey contextKey = "nickname"

// AuthMiddleware validates the bearer token and extracts the nickname from requests.
// GET /api/v1/mode is exempt so the proxy can detect teamserver mode without auth.
func AuthMiddleware(token string, next http.Handler) http.Handler {
	tokenBytes := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow CORS preflight through.
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// Exempt mode endpoint so proxy can detect teamserver before authenticating.
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/mode" {
			next.ServeHTTP(w, r)
			return
		}

		// Check Authorization header first, then query param fallback (for WebSocket).
		provided := ""
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			provided = strings.TrimPrefix(auth, "Bearer ")
		} else if t := r.URL.Query().Get("token"); t != "" {
			provided = t
		}

		if subtle.ConstantTimeCompare(tokenBytes, []byte(provided)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"}) //nolint:errcheck
			return
		}

		nickname := r.Header.Get("X-Joro-Nickname")
		if nickname == "" {
			nickname = r.URL.Query().Get("nickname")
		}
		if nickname == "" {
			nickname = "anonymous"
		}

		ctx := context.WithValue(r.Context(), nicknameKey, nickname)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// NicknameFromContext returns the nickname stored in the request context.
func NicknameFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(nicknameKey).(string); ok {
		return v
	}
	return "anonymous"
}
