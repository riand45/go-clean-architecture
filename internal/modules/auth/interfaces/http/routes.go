// Package http provides HTTP route definitions for the auth module.
package http

import (
	"github.com/gofiber/fiber/v2"
)

// RegisterRoutes registers all auth routes
func RegisterRoutes(app *fiber.App, handler *AuthHandler, middleware *AuthMiddleware) {
	// API version group
	api := app.Group("/api/v1")

	// Auth routes group
	auth := api.Group("/auth")

	// ================================
	// Public Routes (No authentication required)
	// ================================

	// Google OAuth routes
	auth.Get("/google", handler.GetGoogleAuthURL)         // Redirect to Google
	auth.Get("/google/url", handler.GetGoogleAuthURLJSON) // Get URL as JSON (for SPA)
	auth.Get("/google/callback", handler.HandleGoogleCallback)

	// Email OTP routes
	auth.Post("/email/send-otp", handler.SendOTP)
	auth.Post("/email/verify-otp", handler.VerifyOTP)

	// Token refresh (uses refresh token, not access token)
	auth.Post("/refresh", handler.RefreshToken)

	// ================================
	// Protected Routes (Authentication required)
	// ================================

	// Apply auth middleware to protected routes
	protected := auth.Group("", middleware.Authenticate())

	// Logout
	protected.Post("/logout", handler.Logout)

	// Profile routes
	protected.Get("/profile", handler.GetProfile)
	protected.Put("/profile", handler.UpdateProfile)
}

// RegisterHealthRoutes registers health check routes (optional, can be used in main)
func RegisterHealthRoutes(app *fiber.App) {
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status": "healthy",
		})
	})

	app.Get("/ready", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status": "ready",
		})
	})
}
