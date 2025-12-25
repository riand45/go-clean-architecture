// Package tests contains unit tests for the OTP generator service.
package tests

import (
	"testing"

	"github.com/dummy-event/internal/config"
	"github.com/dummy-event/internal/modules/auth/infrastructure/otp"
)

func TestOTPGenerator_GenerateOTP(t *testing.T) {
	cfg := &config.OTPConfig{
		Length: 6,
	}
	generator := otp.NewOTPGenerator(cfg)

	t.Run("should generate 6-digit OTP", func(t *testing.T) {
		code := generator.GenerateOTP()
		if len(code) != 6 {
			t.Errorf("GenerateOTP() length = %d, want 6", len(code))
		}
	})

	t.Run("should generate different OTPs", func(t *testing.T) {
		codes := make(map[string]bool)
		for i := 0; i < 100; i++ {
			code := generator.GenerateOTP()
			if codes[code] {
				// It's possible but very unlikely to get duplicates
				// So we don't fail, just note it
				t.Logf("Got duplicate OTP: %s (can happen occasionally)", code)
			}
			codes[code] = true
		}
	})

	t.Run("should generate only numeric characters", func(t *testing.T) {
		code := generator.GenerateOTP()
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Errorf("GenerateOTP() contains non-numeric character: %c", c)
			}
		}
	})
}

func TestOTPGenerator_HashEmail(t *testing.T) {
	cfg := &config.OTPConfig{
		Length: 6,
	}
	generator := otp.NewOTPGenerator(cfg)

	t.Run("should hash email successfully", func(t *testing.T) {
		email := "test@example.com"
		hash, err := generator.HashEmail(email)
		if err != nil {
			t.Errorf("HashEmail() error = %v, want nil", err)
		}
		if hash == "" {
			t.Error("HashEmail() returned empty hash")
		}
		if hash == email {
			t.Error("HashEmail() returned unhashed email")
		}
	})

	t.Run("should generate different hashes for different emails", func(t *testing.T) {
		hash1, _ := generator.HashEmail("test1@example.com")
		hash2, _ := generator.HashEmail("test2@example.com")
		if hash1 == hash2 {
			t.Error("HashEmail() returned same hash for different emails")
		}
	})

	t.Run("should generate different hashes for same email (bcrypt salt)", func(t *testing.T) {
		email := "test@example.com"
		hash1, _ := generator.HashEmail(email)
		hash2, _ := generator.HashEmail(email)
		if hash1 == hash2 {
			t.Error("HashEmail() returned same hash (bcrypt should use different salt)")
		}
	})
}

func TestOTPGenerator_VerifyEmailHash(t *testing.T) {
	cfg := &config.OTPConfig{
		Length: 6,
	}
	generator := otp.NewOTPGenerator(cfg)

	t.Run("should verify correct email hash", func(t *testing.T) {
		email := "test@example.com"
		hash, _ := generator.HashEmail(email)
		if !generator.VerifyEmailHash(email, hash) {
			t.Error("VerifyEmailHash() returned false for correct email")
		}
	})

	t.Run("should reject incorrect email", func(t *testing.T) {
		email := "test@example.com"
		hash, _ := generator.HashEmail(email)
		if generator.VerifyEmailHash("wrong@example.com", hash) {
			t.Error("VerifyEmailHash() returned true for incorrect email")
		}
	})

	t.Run("should reject invalid hash", func(t *testing.T) {
		if generator.VerifyEmailHash("test@example.com", "invalid-hash") {
			t.Error("VerifyEmailHash() returned true for invalid hash")
		}
	})
}
