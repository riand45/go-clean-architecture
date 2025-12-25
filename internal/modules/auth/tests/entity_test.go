// Package tests contains unit tests for domain entities.
package tests

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/dummy-event/internal/modules/auth/domain/entity"
)

func TestNewUser(t *testing.T) {
	t.Run("should create new user with defaults", func(t *testing.T) {
		user := entity.NewUser("test@example.com", "Test User")

		if user.ID == uuid.Nil {
			t.Error("NewUser() ID should not be nil")
		}
		if user.Email != "test@example.com" {
			t.Errorf("NewUser() Email = %v, want test@example.com", user.Email)
		}
		if user.Name != "Test User" {
			t.Errorf("NewUser() Name = %v, want Test User", user.Name)
		}
		if user.EmailVerified {
			t.Error("NewUser() EmailVerified should be false")
		}
		if user.CreatedAt.IsZero() {
			t.Error("NewUser() CreatedAt should not be zero")
		}
	})
}

func TestNewGoogleUser(t *testing.T) {
	t.Run("should create Google user with email verified", func(t *testing.T) {
		user := entity.NewGoogleUser("test@example.com", "Test User", "https://pic.url", "google-123")

		if user.GoogleID == nil || *user.GoogleID != "google-123" {
			t.Error("NewGoogleUser() GoogleID should be google-123")
		}
		if user.Picture != "https://pic.url" {
			t.Errorf("NewGoogleUser() Picture = %v, want https://pic.url", user.Picture)
		}
		if !user.EmailVerified {
			t.Error("NewGoogleUser() EmailVerified should be true")
		}
	})
}

func TestUser_UpdateProfile(t *testing.T) {
	t.Run("should update profile fields", func(t *testing.T) {
		user := entity.NewUser("test@example.com", "Original Name")
		originalUpdatedAt := user.UpdatedAt

		time.Sleep(1 * time.Millisecond)
		user.UpdateProfile("New Name", "https://new-pic.url")

		if user.Name != "New Name" {
			t.Errorf("UpdateProfile() Name = %v, want New Name", user.Name)
		}
		if user.Picture != "https://new-pic.url" {
			t.Errorf("UpdateProfile() Picture = %v, want https://new-pic.url", user.Picture)
		}
		if !user.UpdatedAt.After(originalUpdatedAt) {
			t.Error("UpdateProfile() should update UpdatedAt")
		}
	})

	t.Run("should not update empty fields", func(t *testing.T) {
		user := entity.NewUser("test@example.com", "Original Name")
		user.Picture = "https://original-pic.url"

		user.UpdateProfile("", "")

		if user.Name != "Original Name" {
			t.Error("UpdateProfile() should not update name when empty")
		}
		if user.Picture != "https://original-pic.url" {
			t.Error("UpdateProfile() should not update picture when empty")
		}
	})
}

func TestUser_HasGoogleLinked(t *testing.T) {
	t.Run("should return true when Google ID exists", func(t *testing.T) {
		user := entity.NewGoogleUser("test@example.com", "Test", "", "google-123")
		if !user.HasGoogleLinked() {
			t.Error("HasGoogleLinked() should return true")
		}
	})

	t.Run("should return false when Google ID is nil", func(t *testing.T) {
		user := entity.NewUser("test@example.com", "Test")
		if user.HasGoogleLinked() {
			t.Error("HasGoogleLinked() should return false")
		}
	})
}

func TestNewTokenPair(t *testing.T) {
	t.Run("should create token pair", func(t *testing.T) {
		now := time.Now().UTC()
		accessExp := now.Add(15 * time.Minute)
		refreshExp := now.Add(7 * 24 * time.Hour)

		pair := entity.NewTokenPair("access-token", "refresh-token", accessExp, refreshExp)

		if pair.AccessToken != "access-token" {
			t.Errorf("NewTokenPair() AccessToken = %v, want access-token", pair.AccessToken)
		}
		if pair.RefreshToken != "refresh-token" {
			t.Errorf("NewTokenPair() RefreshToken = %v, want refresh-token", pair.RefreshToken)
		}
		if pair.TokenType != "Bearer" {
			t.Errorf("NewTokenPair() TokenType = %v, want Bearer", pair.TokenType)
		}
	})
}

func TestOTPToken(t *testing.T) {
	t.Run("should create OTP token", func(t *testing.T) {
		otp := entity.NewOTPToken("hashed-email", "123456", 5*time.Minute)

		if otp.Code != "123456" {
			t.Errorf("NewOTPToken() Code = %v, want 123456", otp.Code)
		}
		if otp.Attempts != 0 {
			t.Errorf("NewOTPToken() Attempts = %v, want 0", otp.Attempts)
		}
	})

	t.Run("should check expiry correctly", func(t *testing.T) {
		// Create expired OTP
		expiredOTP := &entity.OTPToken{
			ExpiresAt: time.Now().UTC().Add(-1 * time.Minute),
		}
		if !expiredOTP.IsExpired() {
			t.Error("IsExpired() should return true for expired OTP")
		}

		// Create valid OTP
		validOTP := entity.NewOTPToken("hash", "123456", 5*time.Minute)
		if validOTP.IsExpired() {
			t.Error("IsExpired() should return false for valid OTP")
		}
	})

	t.Run("should track attempts", func(t *testing.T) {
		otp := entity.NewOTPToken("hash", "123456", 5*time.Minute)

		if !otp.CanAttempt() {
			t.Error("CanAttempt() should return true initially")
		}

		otp.IncrementAttempts()
		otp.IncrementAttempts()
		otp.IncrementAttempts()

		if otp.CanAttempt() {
			t.Error("CanAttempt() should return false after max attempts")
		}
	})

	t.Run("should verify OTP correctly", func(t *testing.T) {
		otp := entity.NewOTPToken("hash", "123456", 5*time.Minute)

		if !otp.Verify("123456") {
			t.Error("Verify() should return true for correct code")
		}
		if otp.Verify("654321") {
			t.Error("Verify() should return false for incorrect code")
		}
	})
}

func TestOAuthState(t *testing.T) {
	t.Run("should create OAuth state", func(t *testing.T) {
		state := entity.NewOAuthState()

		if state.State == "" {
			t.Error("NewOAuthState() State should not be empty")
		}
		if state.IsExpired() {
			t.Error("NewOAuthState() should not be expired immediately")
		}
	})

	t.Run("should check expiry correctly", func(t *testing.T) {
		state := &entity.OAuthState{
			ExpiresAt: time.Now().UTC().Add(-1 * time.Minute),
		}
		if !state.IsExpired() {
			t.Error("IsExpired() should return true for expired state")
		}
	})
}
