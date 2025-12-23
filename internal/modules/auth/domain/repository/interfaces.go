// Package repository defines repository interfaces for the auth module.
// Following the Dependency Inversion Principle, domain layer defines interfaces
// that infrastructure layer implements.
package repository

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/dummy-event/internal/modules/auth/domain/entity"
)

// UserRepository defines operations for user persistence
type UserRepository interface {
	// FindByID retrieves a user by ID
	FindByID(ctx context.Context, id uuid.UUID) (*entity.User, error)

	// FindByEmail retrieves a user by email address
	FindByEmail(ctx context.Context, email string) (*entity.User, error)

	// FindByGoogleID retrieves a user by Google ID
	FindByGoogleID(ctx context.Context, googleID string) (*entity.User, error)

	// Create creates a new user
	Create(ctx context.Context, user *entity.User) error

	// Update updates an existing user
	Update(ctx context.Context, user *entity.User) error

	// UpdateGoogleRefreshToken updates the encrypted Google refresh token
	UpdateGoogleRefreshToken(ctx context.Context, userID uuid.UUID, encryptedToken string) error

	// UpdateLastLogin updates the last login timestamp
	UpdateLastLogin(ctx context.Context, userID uuid.UUID) error
}

// TokenRepository defines operations for token management in Redis
type TokenRepository interface {
	// StoreGoogleAccessToken stores Google access token with TTL
	// Key format: google:access_token:{user_id}
	StoreGoogleAccessToken(ctx context.Context, userID uuid.UUID, token string, expiry time.Duration) error

	// GetGoogleAccessToken retrieves Google access token
	GetGoogleAccessToken(ctx context.Context, userID uuid.UUID) (string, error)

	// DeleteGoogleAccessToken removes Google access token (logout)
	DeleteGoogleAccessToken(ctx context.Context, userID uuid.UUID) error

	// StoreRefreshToken stores application refresh token for lookup
	// Key format: app:refresh_token:{jti}
	StoreRefreshToken(ctx context.Context, jti string, userID uuid.UUID, expiry time.Duration) error

	// GetRefreshTokenUserID retrieves user ID from refresh token JTI
	GetRefreshTokenUserID(ctx context.Context, jti string) (uuid.UUID, error)

	// DeleteRefreshToken removes refresh token (logout/rotation)
	DeleteRefreshToken(ctx context.Context, jti string) error

	// BlacklistToken adds a token JTI to blacklist
	// Key format: blacklist:{jti}
	BlacklistToken(ctx context.Context, jti string, expiry time.Duration) error

	// IsTokenBlacklisted checks if a token is blacklisted
	IsTokenBlacklisted(ctx context.Context, jti string) (bool, error)

	// StoreOAuthState stores OAuth state for CSRF protection
	// Key format: oauth:state:{state}
	StoreOAuthState(ctx context.Context, state string, expiry time.Duration) error

	// ValidateOAuthState validates and consumes OAuth state
	ValidateOAuthState(ctx context.Context, state string) (bool, error)
}

// OTPRepository defines operations for OTP management in Redis
type OTPRepository interface {
	// StoreOTP stores an OTP for email verification
	// Key format: otp:{hashed_email}
	StoreOTP(ctx context.Context, hashedEmail, code string, expiry time.Duration) error

	// GetOTP retrieves OTP by hashed email
	GetOTP(ctx context.Context, hashedEmail string) (string, error)

	// DeleteOTP removes OTP after successful verification
	DeleteOTP(ctx context.Context, hashedEmail string) error

	// IncrementOTPAttempts increments and returns attempt count
	// Key format: otp:attempts:{hashed_email}
	IncrementOTPAttempts(ctx context.Context, hashedEmail string, maxAttempts int) (int, error)

	// ResetOTPAttempts resets the attempt counter
	ResetOTPAttempts(ctx context.Context, hashedEmail string) error
}
