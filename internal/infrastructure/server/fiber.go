// Package server provides Fiber HTTP server setup and configuration.
package server

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"

	"github.com/dummy-event/internal/config"
)

// FiberServer wraps the Fiber app with configuration
type FiberServer struct {
	App *fiber.App
	Cfg *config.AppConfig
}

// NewFiberServer creates a new Fiber server with middleware
func NewFiberServer(cfg *config.AppConfig) *FiberServer {
	app := fiber.New(fiber.Config{
		AppName:               cfg.Name,
		ReadTimeout:           10 * time.Second,
		WriteTimeout:          10 * time.Second,
		IdleTimeout:           120 * time.Second,
		DisableStartupMessage: cfg.IsProduction(),
		ErrorHandler:          customErrorHandler,
	})

	// Middleware: Request ID for tracing
	app.Use(requestid.New())

	// Middleware: Recovery from panics
	app.Use(recover.New(recover.Config{
		EnableStackTrace: cfg.IsDevelopment(),
	}))

	// Middleware: CORS
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "*",
		AllowMethods:     "GET,POST,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Request-ID",
		AllowCredentials: false,
		MaxAge:           86400,
	}))

	// Middleware: Logger (only in development)
	if cfg.IsDevelopment() {
		app.Use(logger.New(logger.Config{
			Format:     "${time} | ${status} | ${latency} | ${ip} | ${method} | ${path} | ${error}\n",
			TimeFormat: "2006-01-02 15:04:05",
			TimeZone:   "Local",
		}))
	}

	// Health check endpoint
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "healthy",
			"service": cfg.Name,
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})

	return &FiberServer{
		App: app,
		Cfg: cfg,
	}
}

// Start starts the server and handles graceful shutdown
func (s *FiberServer) Start() error {
	// Channel to listen for interrupt signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		addr := fmt.Sprintf(":%d", s.Cfg.Port)
		if err := s.App.Listen(addr); err != nil {
			fmt.Printf("Server error: %v\n", err)
		}
	}()

	fmt.Printf("🚀 Server started on port %d\n", s.Cfg.Port)

	// Wait for interrupt signal
	<-quit
	fmt.Println("\n🔴 Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.App.ShutdownWithContext(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	fmt.Println("✅ Server shutdown complete")
	return nil
}

// customErrorHandler handles Fiber errors
func customErrorHandler(c *fiber.Ctx, err error) error {
	// Default to 500 Internal Server Error
	code := fiber.StatusInternalServerError
	message := "Internal Server Error"

	// Check if it's a Fiber error
	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
		message = e.Message
	}

	// Return JSON error response
	return c.Status(code).JSON(fiber.Map{
		"success": false,
		"error": fiber.Map{
			"code":    code,
			"message": message,
		},
	})
}
