//go:build integration
// +build integration

// Package integration contains integration tests that require running Redis.
package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/dummy-event/internal/modules/auth/infrastructure/repository"
)

var testRedisClient *redis.Client

// TestMain sets up the Redis connection for integration tests
func init() {
	ctx := context.Background()

	// Use test Redis URL or default
	redisAddr := os.Getenv("TEST_REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	testRedisClient = redis.NewClient(&redis.Options{
		Addr: redisAddr,
		DB:   15, // Use DB 15 for tests to avoid conflicts
	})

	// Verify connection
	if err := testRedisClient.Ping(ctx).Err(); err != nil {
		testRedisClient = nil
	}
}

func TestTokenRedisRepository_Integration(t *testing.T) {
	if testRedisClient == nil {
		t.Skip("Redis not available, skipping integration tests")
	}

	ctx := context.Background()
	repo := repository.NewTokenRedisRepository(testRedisClient)
	userID := uuid.New()

	t.Run("Store and get Google access token", func(t *testing.T) {
		token := "google-access-token-" + uuid.New().String()
		expiry := 1 * time.Hour

		err := repo.StoreGoogleAccessToken(ctx, userID, token, expiry)
		if err != nil {
			t.Fatalf("StoreGoogleAccessToken() error = %v", err)
		}

		retrieved, err := repo.GetGoogleAccessToken(ctx, userID)
		if err != nil {
			t.Fatalf("GetGoogleAccessToken() error = %v", err)
		}
		if retrieved != token {
			t.Errorf("GetGoogleAccessToken() = %v, want %v", retrieved, token)
		}
	})

	t.Run("Delete Google access token", func(t *testing.T) {
		err := repo.DeleteGoogleAccessToken(ctx, userID)
		if err != nil {
			t.Fatalf("DeleteGoogleAccessToken() error = %v", err)
		}

		retrieved, _ := repo.GetGoogleAccessToken(ctx, userID)
		if retrieved != "" {
			t.Error("GetGoogleAccessToken() should return empty after delete")
		}
	})

	t.Run("Store and get refresh token", func(t *testing.T) {
		jti := "jti-" + uuid.New().String()
		expiry := 7 * 24 * time.Hour

		err := repo.StoreRefreshToken(ctx, jti, userID, expiry)
		if err != nil {
			t.Fatalf("StoreRefreshToken() error = %v", err)
		}

		retrievedUserID, err := repo.GetRefreshTokenUserID(ctx, jti)
		if err != nil {
			t.Fatalf("GetRefreshTokenUserID() error = %v", err)
		}
		if retrievedUserID != userID {
			t.Errorf("GetRefreshTokenUserID() = %v, want %v", retrievedUserID, userID)
		}
	})

	t.Run("Delete refresh token", func(t *testing.T) {
		jti := "jti-delete-" + uuid.New().String()
		repo.StoreRefreshToken(ctx, jti, userID, 1*time.Hour)

		err := repo.DeleteRefreshToken(ctx, jti)
		if err != nil {
			t.Fatalf("DeleteRefreshToken() error = %v", err)
		}
	})

	t.Run("Blacklist token", func(t *testing.T) {
		jti := "blacklist-" + uuid.New().String()

		err := repo.BlacklistToken(ctx, jti, 15*time.Minute)
		if err != nil {
			t.Fatalf("BlacklistToken() error = %v", err)
		}

		isBlacklisted, err := repo.IsTokenBlacklisted(ctx, jti)
		if err != nil {
			t.Fatalf("IsTokenBlacklisted() error = %v", err)
		}
		if !isBlacklisted {
			t.Error("IsTokenBlacklisted() should return true")
		}
	})

	t.Run("Non-blacklisted token", func(t *testing.T) {
		jti := "not-blacklisted-" + uuid.New().String()

		isBlacklisted, err := repo.IsTokenBlacklisted(ctx, jti)
		if err != nil {
			t.Fatalf("IsTokenBlacklisted() error = %v", err)
		}
		if isBlacklisted {
			t.Error("IsTokenBlacklisted() should return false for non-blacklisted token")
		}
	})

	t.Run("OAuth state validation", func(t *testing.T) {
		state := "state-" + uuid.New().String()

		err := repo.StoreOAuthState(ctx, state, 10*time.Minute)
		if err != nil {
			t.Fatalf("StoreOAuthState() error = %v", err)
		}

		// First validation should succeed and consume the state
		valid, err := repo.ValidateOAuthState(ctx, state)
		if err != nil {
			t.Fatalf("ValidateOAuthState() error = %v", err)
		}
		if !valid {
			t.Error("ValidateOAuthState() should return true for valid state")
		}

		// Second validation should fail (state consumed)
		valid, _ = repo.ValidateOAuthState(ctx, state)
		if valid {
			t.Error("ValidateOAuthState() should return false for consumed state")
		}
	})

	t.Run("Token expiry", func(t *testing.T) {
		// Store token with very short TTL
		shortUserID := uuid.New()
		err := repo.StoreGoogleAccessToken(ctx, shortUserID, "short-lived-token", 100*time.Millisecond)
		if err != nil {
			t.Fatalf("StoreGoogleAccessToken() error = %v", err)
		}

		// Wait for expiry
		time.Sleep(200 * time.Millisecond)

		retrieved, _ := repo.GetGoogleAccessToken(ctx, shortUserID)
		if retrieved != "" {
			t.Error("Token should have expired")
		}
	})

	// Cleanup
	t.Cleanup(func() {
		testRedisClient.FlushDB(ctx)
	})
}

func TestOTPRedisRepository_Integration(t *testing.T) {
	if testRedisClient == nil {
		t.Skip("Redis not available, skipping integration tests")
	}

	ctx := context.Background()
	repo := repository.NewOTPRedisRepository(testRedisClient)
	hashedEmail := "hashed-" + uuid.New().String()

	t.Run("Store and get OTP", func(t *testing.T) {
		code := "123456"
		expiry := 5 * time.Minute

		err := repo.StoreOTP(ctx, hashedEmail, code, expiry)
		if err != nil {
			t.Fatalf("StoreOTP() error = %v", err)
		}

		retrieved, err := repo.GetOTP(ctx, hashedEmail)
		if err != nil {
			t.Fatalf("GetOTP() error = %v", err)
		}
		if retrieved != code {
			t.Errorf("GetOTP() = %v, want %v", retrieved, code)
		}
	})

	t.Run("Delete OTP", func(t *testing.T) {
		err := repo.DeleteOTP(ctx, hashedEmail)
		if err != nil {
			t.Fatalf("DeleteOTP() error = %v", err)
		}

		retrieved, _ := repo.GetOTP(ctx, hashedEmail)
		if retrieved != "" {
			t.Error("GetOTP() should return empty after delete")
		}
	})

	t.Run("Increment OTP attempts", func(t *testing.T) {
		attemptEmail := "attempt-" + uuid.New().String()

		count1, err := repo.IncrementOTPAttempts(ctx, attemptEmail, 3)
		if err != nil {
			t.Fatalf("IncrementOTPAttempts() error = %v", err)
		}
		if count1 != 1 {
			t.Errorf("IncrementOTPAttempts() = %v, want 1", count1)
		}

		count2, _ := repo.IncrementOTPAttempts(ctx, attemptEmail, 3)
		if count2 != 2 {
			t.Errorf("IncrementOTPAttempts() = %v, want 2", count2)
		}

		count3, _ := repo.IncrementOTPAttempts(ctx, attemptEmail, 3)
		if count3 != 3 {
			t.Errorf("IncrementOTPAttempts() = %v, want 3", count3)
		}
	})

	t.Run("Reset OTP attempts", func(t *testing.T) {
		resetEmail := "reset-" + uuid.New().String()
		repo.IncrementOTPAttempts(ctx, resetEmail, 3)
		repo.IncrementOTPAttempts(ctx, resetEmail, 3)

		err := repo.ResetOTPAttempts(ctx, resetEmail)
		if err != nil {
			t.Fatalf("ResetOTPAttempts() error = %v", err)
		}

		// After reset, next increment should be 1
		count, _ := repo.IncrementOTPAttempts(ctx, resetEmail, 3)
		if count != 1 {
			t.Errorf("After reset, IncrementOTPAttempts() = %v, want 1", count)
		}
	})

	// Cleanup
	t.Cleanup(func() {
		testRedisClient.FlushDB(ctx)
	})
}
