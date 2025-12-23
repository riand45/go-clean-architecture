// Package service defines service interfaces for the auth module.
package service

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/dummy-event/internal/modules/auth/domain/entity"
)

// JWTService defines JWT token operations using RSA
type JWTService interface {
	// GenerateTokenPair generates access and refresh token pair
	GenerateTokenPair(ctx context.Context, user *entity.User) (*entity.TokenPair, error)

	// ValidateAccessToken validates and parses an access token
	ValidateAccessToken(ctx context.Context, tokenString string) (*entity.JWTClaims, error)

	// ValidateRefreshToken validates and parses a refresh token
	ValidateRefreshToken(ctx context.Context, tokenString string) (*entity.JWTClaims, error)

	// ExtractJTI extracts JTI from token without full validation (for blacklist check)
	ExtractJTI(tokenString string) (string, error)
}

// OAuthService defines Google OAuth operations
type OAuthService interface {
	// GetAuthURL generates the Google OAuth authorization URL
	GetAuthURL(state string) string

	// ExchangeCode exchanges authorization code for tokens
	ExchangeCode(ctx context.Context, code string) (*entity.GoogleToken, error)

	// GetUserInfo retrieves user info from Google using access token
	GetUserInfo(ctx context.Context, accessToken string) (*GoogleUserInfo, error)

	// RefreshAccessToken refreshes Google access token using refresh token
	RefreshAccessToken(ctx context.Context, refreshToken string) (*entity.GoogleToken, error)
}

// GoogleUserInfo represents user information from Google
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

// EmailService defines email sending operations
type EmailService interface {
	// SendOTP sends OTP code to the specified email address
	SendOTP(ctx context.Context, email, otpCode string) error

	// SendWelcome sends a welcome email to new users
	SendWelcome(ctx context.Context, email, name string) error
}

// OTPService defines OTP generation and verification operations
type OTPService interface {
	// GenerateOTP generates a new OTP code
	GenerateOTP() string

	// HashEmail hashes email using bcrypt for secure key storage
	HashEmail(email string) (string, error)

	// VerifyEmailHash verifies email against hash
	VerifyEmailHash(email, hash string) bool
}

// EncryptionService defines encryption/decryption operations for sensitive data
type EncryptionService interface {
	// Encrypt encrypts plaintext using AES-256-GCM
	Encrypt(plaintext string) (string, error)

	// Decrypt decrypts ciphertext using AES-256-GCM
	Decrypt(ciphertext string) (string, error)
}

// AuthUseCase defines the main authentication use case operations
type AuthUseCase interface {
	// Google OAuth flow
	GetGoogleAuthURL(ctx context.Context) (string, error)
	HandleGoogleCallback(ctx context.Context, code, state string) (*entity.TokenPair, *entity.User, error)

	// Email OTP flow
	SendEmailOTP(ctx context.Context, email string) error
	VerifyEmailOTP(ctx context.Context, email, otp string) (*entity.TokenPair, *entity.User, error)

	// Token management
	RefreshToken(ctx context.Context, refreshToken string) (*entity.TokenPair, error)
	Logout(ctx context.Context, accessToken string) error
	ValidateToken(ctx context.Context, accessToken string) (*entity.JWTClaims, error)

	// Profile
	GetProfile(ctx context.Context, userID uuid.UUID) (*entity.User, error)
	UpdateProfile(ctx context.Context, userID uuid.UUID, name, picture string) (*entity.User, error)
}

// SessionInfo represents session information stored in context
type SessionInfo struct {
	UserID    uuid.UUID
	Email     string
	TokenJTI  string
	ExpiresAt time.Time
}
