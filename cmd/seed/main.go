package main

import (
	"context"
	"log"
	"os"

	"github.com/bengobox/auth-service/internal/config"
	"github.com/bengobox/auth-service/internal/database"
	"github.com/bengobox/auth-service/internal/seeding"
	"go.uber.org/zap"
)

// auth-seed: Seeds initial data for auth-service
// This binary is called by Helm hooks or manually for initial setup
// Unlike migrations (which run on startup), seeding is optional and typically runs once
func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("logger: %v", err)
	}
	defer logger.Sync()

	ctx := context.Background()

	client, err := database.NewClient(ctx, cfg.Database)
	if err != nil {
		logger.Fatal("database connection", zap.Error(err))
	}
	defer client.Close()

	// Run migrations first (idempotent)
	if err := database.RunMigrations(ctx, client); err != nil {
		logger.Fatal("migrations", zap.Error(err))
	}
	logger.Info("migrations completed")

	// Seed admin user and default roles
	adminPassword := os.Getenv("SEED_ADMIN_PASSWORD")
	if adminPassword == "" {
		adminPassword = "ChangeMe123!" // Default for development
		logger.Warn("using default admin password - set SEED_ADMIN_PASSWORD in production")
	}

	seeder := seeding.New(client, logger)
	if err := seeder.SeedDefaults(ctx, adminPassword); err != nil {
		logger.Fatal("seeding", zap.Error(err))
	}

	logger.Info("✅ seeding completed successfully")
}
