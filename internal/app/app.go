package app

import (
	"context"
	"fmt"
	"net/http"

	"github.com/bengobox/auth-service/internal/audit"
	"github.com/bengobox/auth-service/internal/cache"
	"github.com/bengobox/auth-service/internal/config"
	"github.com/bengobox/auth-service/internal/database"
	"github.com/bengobox/auth-service/internal/ent"
	"github.com/bengobox/auth-service/internal/httpapi"
	"github.com/bengobox/auth-service/internal/httpapi/handlers"
	httpmiddleware "github.com/bengobox/auth-service/internal/httpapi/middleware"
	"github.com/bengobox/auth-service/internal/password"
	googleprovider "github.com/bengobox/auth-service/internal/providers/google"
	"github.com/bengobox/auth-service/internal/services/auth"
	"github.com/bengobox/auth-service/internal/token"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// App wires core dependencies and exposes server lifecycle controls.
type App struct {
	cfg        *config.Config
	logger     *zap.Logger
	entClient  *ent.Client
	redis      *redis.Client
	httpServer *http.Server
}

// New constructs the application.
func New(ctx context.Context, cfg *config.Config, logger *zap.Logger) (*App, error) {
	entClient, err := database.NewClient(ctx, cfg.Database)
	if err != nil {
		return nil, err
	}
	if cfg.Database.RunMigrations {
		if err := database.RunMigrations(ctx, entClient); err != nil {
			return nil, err
		}
	}

	redisClient, err := cache.New(cfg.Redis)
	if err != nil {
		return nil, err
	}

	tokenSvc, err := token.NewService(cfg.Token)
	if err != nil {
		return nil, err
	}

	googleProvider, err := googleprovider.New(cfg.Providers.Google)
	if err != nil {
		return nil, err
	}

	hasher := password.NewHasher(cfg.Security)
	auditor := audit.New(entClient, logger)

	authService := auth.New(auth.Dependencies{
		EntClient: entClient,
		TokenSvc:  tokenSvc,
		Hasher:    hasher,
		Config:    cfg,
		Auditor:   auditor,
		Logger:    logger,
		Google:    googleProvider,
	})

	authHandler := handlers.NewAuthHandler(authService, logger)
	authMiddleware := httpmiddleware.NewAuth(authService)

	router := httpapi.NewRouter(httpapi.RouterDeps{
		HealthHandler: handlers.Health,
		AuthHandlers: httpapi.AuthHandlers{
			Register:             authHandler.Register,
			Login:                authHandler.Login,
			Refresh:              authHandler.Refresh,
			RequestPasswordReset: authHandler.RequestPasswordReset,
			ConfirmPasswordReset: authHandler.ConfirmPasswordReset,
			Me:                   authHandler.Me,
			GoogleOAuthStart:     authHandler.GoogleOAuthStart,
			GoogleOAuthCallback:  authHandler.GoogleOAuthCallback,
		},
		RequireAuthHandler: authMiddleware.RequireAuth,
	})

	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.HTTP.Host, cfg.HTTP.Port),
		Handler:           router,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
	}

	return &App{
		cfg:        cfg,
		logger:     logger,
		entClient:  entClient,
		redis:      redisClient,
		httpServer: server,
	}, nil
}

// Run starts the HTTP server.
func (a *App) Run() error {
	return a.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the HTTP server and closes resources.
func (a *App) Shutdown(ctx context.Context) error {
	shutdownErr := a.httpServer.Shutdown(ctx)

	if err := a.entClient.Close(); err != nil {
		a.logger.Warn("failed to close ent client", zap.Error(err))
		if shutdownErr == nil {
			shutdownErr = err
		}
	}
	if err := a.redis.Close(); err != nil {
		a.logger.Warn("failed to close redis client", zap.Error(err))
		if shutdownErr == nil {
			shutdownErr = err
		}
	}
	return shutdownErr
}
