// Package main is the entry point for the application.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dummy-event/internal/config"
	"github.com/dummy-event/internal/infrastructure/cache"
	"github.com/dummy-event/internal/infrastructure/database"
	"github.com/dummy-event/internal/infrastructure/server"
	"github.com/dummy-event/internal/modules/auth"
)

func main() {
	// Create root context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	go handleShutdown(cancel)

	// Run the application
	if err := run(ctx); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}

func run(ctx context.Context) error {
	// =================================
	// Load Configuration
	// =================================
	fmt.Println("📦 Loading configuration...")
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	fmt.Printf("✅ Configuration loaded (env: %s)\n", cfg.App.Env)

	// =================================
	// Initialize Database (PostgreSQL)
	// =================================
	fmt.Println("🗄️  Connecting to PostgreSQL...")
	db, err := database.NewPostgresDB(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()
	fmt.Println("✅ PostgreSQL connected")

	// =================================
	// Initialize Cache (Redis)
	// =================================
	fmt.Println("📦 Connecting to Redis...")
	redisClient, err := cache.NewRedisClient(ctx, &cfg.Redis)
	if err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}
	defer redisClient.Close()
	fmt.Println("✅ Redis connected")

	// =================================
	// Initialize HTTP Server
	// =================================
	fmt.Println("🚀 Initializing HTTP server...")
	srv := server.NewFiberServer(&cfg.App)

	// =================================
	// Initialize Modules
	// =================================
	fmt.Println("📦 Initializing modules...")

	// Auth Module
	authModule, err := auth.NewModule(cfg, db.Pool, redisClient.Client)
	if err != nil {
		return fmt.Errorf("failed to initialize auth module: %w", err)
	}
	authModule.RegisterRoutes(srv.App)
	fmt.Println("✅ Auth module initialized")

	// =================================
	// Print Routes (Development)
	// =================================
	if cfg.App.IsDevelopment() {
		fmt.Println("\n📋 Registered Routes:")
		fmt.Println("   Public:")
		fmt.Println("   - GET  /health")
		fmt.Println("   - GET  /api/v1/auth/google")
		fmt.Println("   - GET  /api/v1/auth/google/url")
		fmt.Println("   - GET  /api/v1/auth/google/callback")
		fmt.Println("   - POST /api/v1/auth/email/send-otp")
		fmt.Println("   - POST /api/v1/auth/email/verify-otp")
		fmt.Println("   - POST /api/v1/auth/refresh")
		fmt.Println("   Protected:")
		fmt.Println("   - POST /api/v1/auth/logout")
		fmt.Println("   - GET  /api/v1/auth/profile")
		fmt.Println("   - PUT  /api/v1/auth/profile")
		fmt.Println("")
	}

	// =================================
	// Start Server
	// =================================
	fmt.Printf("🌐 Server starting on port %d...\n\n", cfg.App.Port)
	return srv.Start()
}

// handleShutdown handles graceful shutdown signals
func handleShutdown(cancel context.CancelFunc) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	<-quit

	fmt.Println("\n🔴 Shutdown signal received...")

	// Cancel context
	cancel()

	// Give some time for cleanup
	time.Sleep(2 * time.Second)
}
