// Package http provides HTTP middleware for the auth module.
package http

import (
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/dummy-event/internal/modules/auth/application/dto"
	"github.com/dummy-event/internal/modules/auth/domain/entity"
	"github.com/dummy-event/internal/modules/auth/domain/service"
)

// Context keys for storing auth information
const (
	ContextKeyUserID = "user_id"
	ContextKeyClaims = "claims"
)

// AuthMiddleware provides JWT authentication middleware
type AuthMiddleware struct {
	authUseCase service.AuthUseCase
}

// NewAuthMiddleware creates a new AuthMiddleware
func NewAuthMiddleware(authUseCase service.AuthUseCase) *AuthMiddleware {
	return &AuthMiddleware{
		authUseCase: authUseCase,
	}
}

// Authenticate validates JWT token and sets user context
func (m *AuthMiddleware) Authenticate() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get token from Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(
				dto.NewErrorResponse(fiber.StatusUnauthorized, "Authorization header is required"),
			)
		}

		// Extract token from "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return c.Status(fiber.StatusUnauthorized).JSON(
				dto.NewErrorResponse(fiber.StatusUnauthorized, "Invalid authorization header format"),
			)
		}

		token := parts[1]

		// Validate token
		claims, err := m.authUseCase.ValidateToken(c.Context(), token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(
				dto.NewErrorResponse(fiber.StatusUnauthorized, "Invalid or expired token"),
			)
		}

		// Set user info in context
		c.Locals(ContextKeyUserID, claims.UserID.String())
		c.Locals(ContextKeyClaims, claims)

		return c.Next()
	}
}

// OptionalAuthenticate validates JWT token if present, but doesn't require it
func (m *AuthMiddleware) OptionalAuthenticate() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Next()
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return c.Next()
		}

		token := parts[1]

		claims, err := m.authUseCase.ValidateToken(c.Context(), token)
		if err != nil {
			return c.Next()
		}

		c.Locals(ContextKeyUserID, claims.UserID.String())
		c.Locals(ContextKeyClaims, claims)

		return c.Next()
	}
}

// GetUserIDFromContext retrieves user ID from Fiber context
func GetUserIDFromContext(c *fiber.Ctx) string {
	userID := c.Locals(ContextKeyUserID)
	if userID == nil {
		return ""
	}
	return userID.(string)
}

// GetClaimsFromContext retrieves JWT claims from Fiber context
func GetClaimsFromContext(c *fiber.Ctx) *entity.JWTClaims {
	claims := c.Locals(ContextKeyClaims)
	if claims == nil {
		return nil
	}
	return claims.(*entity.JWTClaims)
}
