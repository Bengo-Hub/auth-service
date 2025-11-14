package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bengobox/auth-service/internal/token"
)

// TokenValidator defines the capabilities required to validate JWTs.
type TokenValidator interface {
	ValidateAccessToken(tokenStr string) (*token.Claims, error)
}

// Auth provides JWT-backed authentication middleware.
type Auth struct {
	validator TokenValidator
}

// NewAuth creates a new instance.
func NewAuth(validator TokenValidator) *Auth {
	return &Auth{validator: validator}
}

// RequireAuth ensures incoming requests possess a valid bearer token.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			writeAuthError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}

		tokenStr := strings.TrimSpace(authHeader[7:])
		claims, err := a.validator.ValidateAccessToken(tokenStr)
		if err != nil {
			writeAuthError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		ctx := context.WithValue(r.Context(), claimsContextKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": message,
		"code":  "unauthorized",
	})
}

type claimsContextKey struct{}

// ClaimsFromContext extracts token claims stored by middleware.
func ClaimsFromContext(ctx context.Context) (*token.Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey{}).(*token.Claims)
	return claims, ok && claims != nil
}
