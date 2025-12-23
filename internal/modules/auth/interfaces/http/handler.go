// Package http provides HTTP handlers for the auth module.
package http

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/dummy-event/internal/modules/auth/application/dto"
	"github.com/dummy-event/internal/modules/auth/domain/entity"
	"github.com/dummy-event/internal/modules/auth/domain/service"
)

// AuthHandler handles authentication HTTP requests
type AuthHandler struct {
	authUseCase service.AuthUseCase
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(authUseCase service.AuthUseCase) *AuthHandler {
	return &AuthHandler{
		authUseCase: authUseCase,
	}
}

// ================================
// Google OAuth Handlers
// ================================

// GetGoogleAuthURL redirects to Google OAuth authorization URL
// @Summary Redirect to Google OAuth
// @Description Initiates Google OAuth flow by redirecting to Google's authorization page
// @Tags Auth
// @Produce json
// @Success 302 {string} string "Redirect to Google OAuth"
// @Failure 500 {object} dto.ErrorResponse
// @Router /auth/google [get]
func (h *AuthHandler) GetGoogleAuthURL(c *fiber.Ctx) error {
	authURL, err := h.authUseCase.GetGoogleAuthURL(c.Context())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(
			dto.NewErrorResponse(fiber.StatusInternalServerError, "Failed to generate OAuth URL"),
		)
	}

	// Redirect to Google OAuth
	return c.Redirect(authURL, fiber.StatusTemporaryRedirect)
}

// GetGoogleAuthURLJSON returns Google OAuth URL as JSON (for SPA apps)
// @Summary Get Google OAuth URL
// @Description Returns Google OAuth authorization URL for SPA applications
// @Tags Auth
// @Produce json
// @Success 200 {object} dto.SuccessResponse{data=dto.GoogleAuthURLResponse}
// @Failure 500 {object} dto.ErrorResponse
// @Router /auth/google/url [get]
func (h *AuthHandler) GetGoogleAuthURLJSON(c *fiber.Ctx) error {
	authURL, err := h.authUseCase.GetGoogleAuthURL(c.Context())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(
			dto.NewErrorResponse(fiber.StatusInternalServerError, "Failed to generate OAuth URL"),
		)
	}

	return c.JSON(dto.NewSuccessResponse(dto.GoogleAuthURLResponse{
		AuthURL: authURL,
	}))
}

// HandleGoogleCallback handles Google OAuth callback
// @Summary Handle Google OAuth callback
// @Description Handles callback from Google OAuth, exchanges code for tokens
// @Tags Auth
// @Produce json
// @Param code query string true "Authorization code from Google"
// @Param state query string true "OAuth state for CSRF protection"
// @Success 200 {object} dto.SuccessResponse{data=dto.AuthResponse}
// @Failure 400 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /auth/google/callback [get]
func (h *AuthHandler) HandleGoogleCallback(c *fiber.Ctx) error {
	code := c.Query("code")
	state := c.Query("state")

	if code == "" {
		return c.Status(fiber.StatusBadRequest).JSON(
			dto.NewErrorResponse(fiber.StatusBadRequest, "Authorization code is required"),
		)
	}

	if state == "" {
		return c.Status(fiber.StatusBadRequest).JSON(
			dto.NewErrorResponse(fiber.StatusBadRequest, "OAuth state is required"),
		)
	}

	tokenPair, user, err := h.authUseCase.HandleGoogleCallback(c.Context(), code, state)
	if err != nil {
		// Log the actual error for debugging
		fmt.Printf("❌ Google OAuth callback error: %v\n", err)

		// Check for specific errors
		errMsg := err.Error()
		if strings.Contains(errMsg, "invalid or expired OAuth state") {
			return c.Status(fiber.StatusBadRequest).JSON(
				dto.NewErrorResponse(fiber.StatusBadRequest, "Invalid or expired OAuth state. Please try again."),
			)
		}
		return c.Status(fiber.StatusInternalServerError).JSON(
			dto.NewErrorResponse(fiber.StatusInternalServerError, "Authentication failed"),
		)
	}

	return c.JSON(dto.NewSuccessResponse(h.buildAuthResponse(tokenPair, user, false)))
}

// ================================
// Email OTP Handlers
// ================================

// SendOTP sends an OTP to the specified email
// @Summary Send OTP to email
// @Description Sends a 6-digit OTP to the provided email address for verification
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.SendOTPRequest true "Email address"
// @Success 200 {object} dto.SuccessResponse{data=dto.OTPSentResponse}
// @Failure 400 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /auth/email/send-otp [post]
func (h *AuthHandler) SendOTP(c *fiber.Ctx) error {
	var req dto.SendOTPRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			dto.NewErrorResponse(fiber.StatusBadRequest, "Invalid request body"),
		)
	}

	// Basic email validation
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		return c.Status(fiber.StatusBadRequest).JSON(
			dto.NewErrorResponse(fiber.StatusBadRequest, "Valid email is required"),
		)
	}

	if err := h.authUseCase.SendEmailOTP(c.Context(), req.Email); err != nil {
		// Don't expose internal errors
		return c.Status(fiber.StatusInternalServerError).JSON(
			dto.NewErrorResponse(fiber.StatusInternalServerError, "Failed to send OTP. Please try again."),
		)
	}

	return c.JSON(dto.NewSuccessResponse(dto.OTPSentResponse{
		Message:   "OTP sent successfully",
		Email:     req.Email,
		ExpiresAt: c.Context().Time().Add(5 * 60 * 1000000000), // 5 minutes
	}))
}

// VerifyOTP verifies the OTP and logs in the user
// @Summary Verify OTP and login
// @Description Verifies the OTP sent to email and returns authentication tokens
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.VerifyOTPRequest true "Email and OTP"
// @Success 200 {object} dto.SuccessResponse{data=dto.AuthResponse}
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /auth/email/verify-otp [post]
func (h *AuthHandler) VerifyOTP(c *fiber.Ctx) error {
	var req dto.VerifyOTPRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			dto.NewErrorResponse(fiber.StatusBadRequest, "Invalid request body"),
		)
	}

	if req.Email == "" || req.OTP == "" {
		return c.Status(fiber.StatusBadRequest).JSON(
			dto.NewErrorResponse(fiber.StatusBadRequest, "Email and OTP are required"),
		)
	}

	if len(req.OTP) != 6 {
		return c.Status(fiber.StatusBadRequest).JSON(
			dto.NewErrorResponse(fiber.StatusBadRequest, "OTP must be 6 digits"),
		)
	}

	tokenPair, user, err := h.authUseCase.VerifyEmailOTP(c.Context(), req.Email, req.OTP)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "invalid OTP") {
			return c.Status(fiber.StatusUnauthorized).JSON(
				dto.NewErrorResponse(fiber.StatusUnauthorized, "Invalid OTP"),
			)
		}
		if strings.Contains(errMsg, "expired") || strings.Contains(errMsg, "not found") {
			return c.Status(fiber.StatusBadRequest).JSON(
				dto.NewErrorResponse(fiber.StatusBadRequest, "OTP expired or not found. Please request a new OTP."),
			)
		}
		if strings.Contains(errMsg, "maximum") {
			return c.Status(fiber.StatusTooManyRequests).JSON(
				dto.NewErrorResponse(fiber.StatusTooManyRequests, "Maximum OTP attempts exceeded. Please request a new OTP."),
			)
		}
		return c.Status(fiber.StatusInternalServerError).JSON(
			dto.NewErrorResponse(fiber.StatusInternalServerError, "Verification failed"),
		)
	}

	return c.JSON(dto.NewSuccessResponse(h.buildAuthResponse(tokenPair, user, false)))
}

// ================================
// Token Management Handlers
// ================================

// RefreshToken exchanges a refresh token for new tokens
// @Summary Refresh access token
// @Description Exchanges a valid refresh token for a new access/refresh token pair
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.RefreshTokenRequest true "Refresh token"
// @Success 200 {object} dto.SuccessResponse{data=dto.TokenResponse}
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /auth/refresh [post]
func (h *AuthHandler) RefreshToken(c *fiber.Ctx) error {
	var req dto.RefreshTokenRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			dto.NewErrorResponse(fiber.StatusBadRequest, "Invalid request body"),
		)
	}

	if req.RefreshToken == "" {
		return c.Status(fiber.StatusBadRequest).JSON(
			dto.NewErrorResponse(fiber.StatusBadRequest, "Refresh token is required"),
		)
	}

	tokenPair, err := h.authUseCase.RefreshToken(c.Context(), req.RefreshToken)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(
			dto.NewErrorResponse(fiber.StatusUnauthorized, "Invalid or expired refresh token"),
		)
	}

	return c.JSON(dto.NewSuccessResponse(dto.TokenResponse{
		AccessToken:           tokenPair.AccessToken,
		RefreshToken:          tokenPair.RefreshToken,
		AccessTokenExpiresAt:  tokenPair.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: tokenPair.RefreshTokenExpiresAt,
		TokenType:             tokenPair.TokenType,
	}))
}

// Logout revokes the current session
// @Summary Logout
// @Description Revokes the current access token and ends the session
// @Tags Auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} dto.SuccessResponse{data=dto.MessageResponse}
// @Failure 401 {object} dto.ErrorResponse
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c *fiber.Ctx) error {
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

	if err := h.authUseCase.Logout(c.Context(), token); err != nil {
		// Still return success even if there's an error (token might be already expired)
		// This is a security best practice - don't reveal token state
	}

	return c.JSON(dto.NewSuccessResponse(dto.MessageResponse{
		Message: "Logged out successfully",
	}))
}

// ================================
// Profile Handlers
// ================================

// GetProfile returns the current user's profile
// @Summary Get user profile
// @Description Returns the profile of the authenticated user
// @Tags Auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} dto.SuccessResponse{data=dto.UserResponse}
// @Failure 401 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /auth/profile [get]
func (h *AuthHandler) GetProfile(c *fiber.Ctx) error {
	// Get user ID from context (set by auth middleware)
	userID := GetUserIDFromContext(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(
			dto.NewErrorResponse(fiber.StatusUnauthorized, "Unauthorized"),
		)
	}

	claims := GetClaimsFromContext(c)
	if claims == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(
			dto.NewErrorResponse(fiber.StatusUnauthorized, "Unauthorized"),
		)
	}

	user, err := h.authUseCase.GetProfile(c.Context(), claims.UserID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(
			dto.NewErrorResponse(fiber.StatusNotFound, "User not found"),
		)
	}

	return c.JSON(dto.NewSuccessResponse(h.buildUserResponse(user)))
}

// UpdateProfile updates the current user's profile
// @Summary Update user profile
// @Description Updates the profile of the authenticated user
// @Tags Auth
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body dto.UpdateProfileRequest true "Profile update data"
// @Success 200 {object} dto.SuccessResponse{data=dto.UserResponse}
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /auth/profile [put]
func (h *AuthHandler) UpdateProfile(c *fiber.Ctx) error {
	claims := GetClaimsFromContext(c)
	if claims == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(
			dto.NewErrorResponse(fiber.StatusUnauthorized, "Unauthorized"),
		)
	}

	var req dto.UpdateProfileRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			dto.NewErrorResponse(fiber.StatusBadRequest, "Invalid request body"),
		)
	}

	user, err := h.authUseCase.UpdateProfile(c.Context(), claims.UserID, req.Name, req.Picture)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return c.Status(fiber.StatusNotFound).JSON(
				dto.NewErrorResponse(fiber.StatusNotFound, "User not found"),
			)
		}
		return c.Status(fiber.StatusInternalServerError).JSON(
			dto.NewErrorResponse(fiber.StatusInternalServerError, "Failed to update profile"),
		)
	}

	return c.JSON(dto.NewSuccessResponse(h.buildUserResponse(user)))
}

// ================================
// Helper Methods
// ================================

// buildAuthResponse builds the authentication response
func (h *AuthHandler) buildAuthResponse(tokenPair *entity.TokenPair, user *entity.User, isNewUser bool) dto.AuthResponse {
	return dto.AuthResponse{
		User:      h.buildUserResponse(user),
		Tokens:    h.buildTokenResponse(tokenPair),
		IsNewUser: isNewUser,
	}
}

// buildUserResponse builds the user response
func (h *AuthHandler) buildUserResponse(user *entity.User) dto.UserResponse {
	return dto.UserResponse{
		ID:            user.ID.String(),
		Email:         user.Email,
		Name:          user.Name,
		Picture:       user.Picture,
		EmailVerified: user.EmailVerified,
		CreatedAt:     user.CreatedAt,
		LastLoginAt:   user.LastLoginAt,
	}
}

// buildTokenResponse builds the token response
func (h *AuthHandler) buildTokenResponse(tokenPair *entity.TokenPair) dto.TokenResponse {
	return dto.TokenResponse{
		AccessToken:           tokenPair.AccessToken,
		RefreshToken:          tokenPair.RefreshToken,
		AccessTokenExpiresAt:  tokenPair.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: tokenPair.RefreshTokenExpiresAt,
		TokenType:             tokenPair.TokenType,
	}
}
