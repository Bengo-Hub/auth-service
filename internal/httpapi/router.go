package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

// RouterDeps defines router construction dependencies.
type RouterDeps struct {
	HealthHandler      http.HandlerFunc
	AuthHandlers       AuthHandlers
	RequireAuthHandler func(http.Handler) http.Handler
}

// AuthHandlers groups the HTTP handlers for auth routes.
type AuthHandlers struct {
	Register             http.HandlerFunc
	Login                http.HandlerFunc
	Refresh              http.HandlerFunc
	RequestPasswordReset http.HandlerFunc
	ConfirmPasswordReset http.HandlerFunc
	Me                   http.HandlerFunc
	GoogleOAuthStart     http.HandlerFunc
	GoogleOAuthCallback  http.HandlerFunc
}

// NewRouter wires HTTP routes.
func NewRouter(deps RouterDeps) http.Handler {
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(60 * time.Second))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	if deps.HealthHandler != nil {
		r.Get("/healthz", deps.HealthHandler)
	}

	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.Post("/register", deps.AuthHandlers.Register)
			r.Post("/login", deps.AuthHandlers.Login)
			r.Post("/refresh", deps.AuthHandlers.Refresh)
			r.Post("/password-reset/request", deps.AuthHandlers.RequestPasswordReset)
			r.Post("/password-reset/confirm", deps.AuthHandlers.ConfirmPasswordReset)
			r.Post("/oauth/google/start", deps.AuthHandlers.GoogleOAuthStart)
			r.Get("/oauth/google/callback", deps.AuthHandlers.GoogleOAuthCallback)

			r.Group(func(r chi.Router) {
				if deps.RequireAuthHandler != nil {
					r.Use(deps.RequireAuthHandler)
				}
				r.Get("/me", deps.AuthHandlers.Me)
			})
		})
	})

	return r
}
