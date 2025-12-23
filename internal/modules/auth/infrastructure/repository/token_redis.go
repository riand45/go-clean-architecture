// Package repository implements repository interfaces using Redis.
package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/dummy-event/internal/modules/auth/domain/repository"
)

// Redis key prefixes for different token types
const (
	keyPrefixGoogleAccessToken = "google:access_token:"
	keyPrefixRefreshToken      = "app:refresh_token:"
	keyPrefixBlacklist         = "blacklist:"
	keyPrefixOAuthState        = "oauth:state:"
	keyPrefixOTP               = "otp:"
	keyPrefixOTPAttempts       = "otp:attempts:"
)

// Ensure implementations satisfy interfaces
var (
	_ repository.TokenRepository = (*TokenRedisRepository)(nil)
	_ repository.OTPRepository   = (*OTPRedisRepository)(nil)
)

// TokenRedisRepository implements TokenRepository using Redis
type TokenRedisRepository struct {
	client *redis.Client
}

// NewTokenRedisRepository creates a new TokenRedisRepository
func NewTokenRedisRepository(client *redis.Client) *TokenRedisRepository {
	return &TokenRedisRepository{client: client}
}

// StoreGoogleAccessToken stores Google access token with TTL
func (r *TokenRedisRepository) StoreGoogleAccessToken(ctx context.Context, userID uuid.UUID, token string, expiry time.Duration) error {
	key := keyPrefixGoogleAccessToken + userID.String()
	if err := r.client.Set(ctx, key, token, expiry).Err(); err != nil {
		return fmt.Errorf("failed to store Google access token: %w", err)
	}
	return nil
}

// GetGoogleAccessToken retrieves Google access token
func (r *TokenRedisRepository) GetGoogleAccessToken(ctx context.Context, userID uuid.UUID) (string, error) {
	key := keyPrefixGoogleAccessToken + userID.String()
	token, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", nil // Token not found or expired
		}
		return "", fmt.Errorf("failed to get Google access token: %w", err)
	}
	return token, nil
}

// DeleteGoogleAccessToken removes Google access token (logout)
func (r *TokenRedisRepository) DeleteGoogleAccessToken(ctx context.Context, userID uuid.UUID) error {
	key := keyPrefixGoogleAccessToken + userID.String()
	if err := r.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete Google access token: %w", err)
	}
	return nil
}

// StoreRefreshToken stores application refresh token for lookup
func (r *TokenRedisRepository) StoreRefreshToken(ctx context.Context, jti string, userID uuid.UUID, expiry time.Duration) error {
	key := keyPrefixRefreshToken + jti
	if err := r.client.Set(ctx, key, userID.String(), expiry).Err(); err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}
	return nil
}

// GetRefreshTokenUserID retrieves user ID from refresh token JTI
func (r *TokenRedisRepository) GetRefreshTokenUserID(ctx context.Context, jti string) (uuid.UUID, error) {
	key := keyPrefixRefreshToken + jti
	userIDStr, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return uuid.Nil, fmt.Errorf("refresh token not found or expired")
		}
		return uuid.Nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID in refresh token: %w", err)
	}

	return userID, nil
}

// DeleteRefreshToken removes refresh token (logout/rotation)
func (r *TokenRedisRepository) DeleteRefreshToken(ctx context.Context, jti string) error {
	key := keyPrefixRefreshToken + jti
	if err := r.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}
	return nil
}

// BlacklistToken adds a token JTI to blacklist
func (r *TokenRedisRepository) BlacklistToken(ctx context.Context, jti string, expiry time.Duration) error {
	key := keyPrefixBlacklist + jti
	if err := r.client.Set(ctx, key, "revoked", expiry).Err(); err != nil {
		return fmt.Errorf("failed to blacklist token: %w", err)
	}
	return nil
}

// IsTokenBlacklisted checks if a token is blacklisted
func (r *TokenRedisRepository) IsTokenBlacklisted(ctx context.Context, jti string) (bool, error) {
	key := keyPrefixBlacklist + jti
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check token blacklist: %w", err)
	}
	return exists > 0, nil
}

// StoreOAuthState stores OAuth state for CSRF protection
func (r *TokenRedisRepository) StoreOAuthState(ctx context.Context, state string, expiry time.Duration) error {
	key := keyPrefixOAuthState + state
	if err := r.client.Set(ctx, key, "valid", expiry).Err(); err != nil {
		return fmt.Errorf("failed to store OAuth state: %w", err)
	}
	return nil
}

// ValidateOAuthState validates and consumes OAuth state
func (r *TokenRedisRepository) ValidateOAuthState(ctx context.Context, state string) (bool, error) {
	key := keyPrefixOAuthState + state

	// Use GetDel to atomically get and delete (prevents replay attacks)
	result, err := r.client.GetDel(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return false, nil // State not found or already used
		}
		return false, fmt.Errorf("failed to validate OAuth state: %w", err)
	}

	return result == "valid", nil
}

// OTPRedisRepository implements OTPRepository using Redis
type OTPRedisRepository struct {
	client *redis.Client
}

// NewOTPRedisRepository creates a new OTPRedisRepository
func NewOTPRedisRepository(client *redis.Client) *OTPRedisRepository {
	return &OTPRedisRepository{client: client}
}

// StoreOTP stores an OTP for email verification
func (r *OTPRedisRepository) StoreOTP(ctx context.Context, hashedEmail, code string, expiry time.Duration) error {
	key := keyPrefixOTP + hashedEmail
	if err := r.client.Set(ctx, key, code, expiry).Err(); err != nil {
		return fmt.Errorf("failed to store OTP: %w", err)
	}
	return nil
}

// GetOTP retrieves OTP by hashed email
func (r *OTPRedisRepository) GetOTP(ctx context.Context, hashedEmail string) (string, error) {
	key := keyPrefixOTP + hashedEmail
	code, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", nil // OTP not found or expired
		}
		return "", fmt.Errorf("failed to get OTP: %w", err)
	}
	return code, nil
}

// DeleteOTP removes OTP after successful verification
func (r *OTPRedisRepository) DeleteOTP(ctx context.Context, hashedEmail string) error {
	key := keyPrefixOTP + hashedEmail
	if err := r.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete OTP: %w", err)
	}
	return nil
}

// IncrementOTPAttempts increments and returns attempt count
func (r *OTPRedisRepository) IncrementOTPAttempts(ctx context.Context, hashedEmail string, maxAttempts int) (int, error) {
	key := keyPrefixOTPAttempts + hashedEmail

	// Increment and get the new value
	count, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to increment OTP attempts: %w", err)
	}

	// Set expiry on first attempt (same as OTP expiry)
	if count == 1 {
		r.client.Expire(ctx, key, 5*time.Minute)
	}

	return int(count), nil
}

// ResetOTPAttempts resets the attempt counter
func (r *OTPRedisRepository) ResetOTPAttempts(ctx context.Context, hashedEmail string) error {
	key := keyPrefixOTPAttempts + hashedEmail
	if err := r.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to reset OTP attempts: %w", err)
	}
	return nil
}
