// Package tests contains unit tests for the auth usecase.
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/dummy-event/internal/config"
	"github.com/dummy-event/internal/modules/auth/application/usecase"
	"github.com/dummy-event/internal/modules/auth/domain/entity"
	"github.com/dummy-event/internal/modules/auth/domain/service"
	"github.com/dummy-event/internal/modules/auth/tests/mocks"
)

// TestAuthUseCase_GetGoogleAuthURL tests the GetGoogleAuthURL use case
func TestAuthUseCase_GetGoogleAuthURL(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			RefreshTokenExpire: 7 * 24 * time.Hour,
		},
	}

	userRepo := mocks.NewMockUserRepository()
	tokenRepo := mocks.NewMockTokenRepository()
	otpRepo := mocks.NewMockOTPRepository()
	jwtService := mocks.NewMockJWTService()
	oauthService := mocks.NewMockOAuthService()
	emailService := mocks.NewMockEmailService()
	otpService := mocks.NewMockOTPService()
	encryptionService := mocks.NewMockEncryptionService()

	authUseCase := usecase.NewAuthUseCase(
		cfg,
		userRepo,
		tokenRepo,
		otpRepo,
		jwtService,
		oauthService,
		emailService,
		otpService,
		encryptionService,
	)

	ctx := context.Background()

	t.Run("should return auth URL", func(t *testing.T) {
		url, err := authUseCase.GetGoogleAuthURL(ctx)
		if err != nil {
			t.Errorf("GetGoogleAuthURL() error = %v, want nil", err)
		}
		if url == "" {
			t.Error("GetGoogleAuthURL() returned empty URL")
		}
		if len(tokenRepo.OAuthStates) != 1 {
			t.Error("OAuth state was not stored in repository")
		}
	})
}

// TestAuthUseCase_HandleGoogleCallback tests the HandleGoogleCallback use case
func TestAuthUseCase_HandleGoogleCallback(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			RefreshTokenExpire: 7 * 24 * time.Hour,
		},
	}

	t.Run("should create new user on first login", func(t *testing.T) {
		userRepo := mocks.NewMockUserRepository()
		tokenRepo := mocks.NewMockTokenRepository()
		otpRepo := mocks.NewMockOTPRepository()
		jwtService := mocks.NewMockJWTService()
		oauthService := mocks.NewMockOAuthService()
		emailService := mocks.NewMockEmailService()
		otpService := mocks.NewMockOTPService()
		encryptionService := mocks.NewMockEncryptionService()

		authUseCase := usecase.NewAuthUseCase(
			cfg,
			userRepo,
			tokenRepo,
			otpRepo,
			jwtService,
			oauthService,
			emailService,
			otpService,
			encryptionService,
		)

		ctx := context.Background()

		// Store OAuth state first
		tokenRepo.OAuthStates["valid-state"] = true

		tokenPair, user, err := authUseCase.HandleGoogleCallback(ctx, "valid-code", "valid-state")
		if err != nil {
			t.Errorf("HandleGoogleCallback() error = %v, want nil", err)
		}
		if tokenPair == nil {
			t.Error("HandleGoogleCallback() returned nil tokenPair")
		}
		if user == nil {
			t.Error("HandleGoogleCallback() returned nil user")
		}
		if user != nil && user.Email != "test@example.com" {
			t.Errorf("HandleGoogleCallback() user.Email = %v, want test@example.com", user.Email)
		}
	})

	t.Run("should fail with invalid state", func(t *testing.T) {
		userRepo := mocks.NewMockUserRepository()
		tokenRepo := mocks.NewMockTokenRepository()
		otpRepo := mocks.NewMockOTPRepository()
		jwtService := mocks.NewMockJWTService()
		oauthService := mocks.NewMockOAuthService()
		emailService := mocks.NewMockEmailService()
		otpService := mocks.NewMockOTPService()
		encryptionService := mocks.NewMockEncryptionService()

		authUseCase := usecase.NewAuthUseCase(
			cfg,
			userRepo,
			tokenRepo,
			otpRepo,
			jwtService,
			oauthService,
			emailService,
			otpService,
			encryptionService,
		)

		ctx := context.Background()

		_, _, err := authUseCase.HandleGoogleCallback(ctx, "valid-code", "invalid-state")
		if err == nil {
			t.Error("HandleGoogleCallback() expected error for invalid state, got nil")
		}
	})

	t.Run("should return existing user on subsequent login", func(t *testing.T) {
		userRepo := mocks.NewMockUserRepository()
		tokenRepo := mocks.NewMockTokenRepository()
		otpRepo := mocks.NewMockOTPRepository()
		jwtService := mocks.NewMockJWTService()
		oauthService := mocks.NewMockOAuthService()
		emailService := mocks.NewMockEmailService()
		otpService := mocks.NewMockOTPService()
		encryptionService := mocks.NewMockEncryptionService()

		// Add existing user
		googleID := "google-user-id-123"
		existingUser := &entity.User{
			ID:       uuid.New(),
			Email:    "test@example.com",
			Name:     "Existing User",
			GoogleID: &googleID,
		}
		userRepo.AddUser(existingUser)

		authUseCase := usecase.NewAuthUseCase(
			cfg,
			userRepo,
			tokenRepo,
			otpRepo,
			jwtService,
			oauthService,
			emailService,
			otpService,
			encryptionService,
		)

		ctx := context.Background()
		tokenRepo.OAuthStates["valid-state"] = true

		tokenPair, user, err := authUseCase.HandleGoogleCallback(ctx, "valid-code", "valid-state")
		if err != nil {
			t.Errorf("HandleGoogleCallback() error = %v, want nil", err)
		}
		if tokenPair == nil {
			t.Error("HandleGoogleCallback() returned nil tokenPair")
		}
		if user == nil {
			t.Error("HandleGoogleCallback() returned nil user")
		}
		if user != nil && user.ID != existingUser.ID {
			t.Errorf("HandleGoogleCallback() returned different user, got %v, want %v", user.ID, existingUser.ID)
		}
	})
}

// TestAuthUseCase_SendEmailOTP tests the SendEmailOTP use case
func TestAuthUseCase_SendEmailOTP(t *testing.T) {
	cfg := &config.Config{
		OTP: config.OTPConfig{
			Length:        6,
			ExpireMinutes: 5 * time.Minute,
		},
	}

	t.Run("should send OTP successfully", func(t *testing.T) {
		userRepo := mocks.NewMockUserRepository()
		tokenRepo := mocks.NewMockTokenRepository()
		otpRepo := mocks.NewMockOTPRepository()
		jwtService := mocks.NewMockJWTService()
		oauthService := mocks.NewMockOAuthService()
		emailService := mocks.NewMockEmailService()
		otpService := mocks.NewMockOTPService()
		encryptionService := mocks.NewMockEncryptionService()

		authUseCase := usecase.NewAuthUseCase(
			cfg,
			userRepo,
			tokenRepo,
			otpRepo,
			jwtService,
			oauthService,
			emailService,
			otpService,
			encryptionService,
		)

		ctx := context.Background()
		email := "user@example.com"

		err := authUseCase.SendEmailOTP(ctx, email)
		if err != nil {
			t.Errorf("SendEmailOTP() error = %v, want nil", err)
		}

		if emailService.SentOTPs[email] == "" {
			t.Error("SendEmailOTP() OTP was not sent via email")
		}
	})

	t.Run("should fail when email service fails", func(t *testing.T) {
		userRepo := mocks.NewMockUserRepository()
		tokenRepo := mocks.NewMockTokenRepository()
		otpRepo := mocks.NewMockOTPRepository()
		jwtService := mocks.NewMockJWTService()
		oauthService := mocks.NewMockOAuthService()
		emailService := mocks.NewMockEmailService()
		otpService := mocks.NewMockOTPService()
		encryptionService := mocks.NewMockEncryptionService()

		emailService.SendOTPErr = context.DeadlineExceeded

		authUseCase := usecase.NewAuthUseCase(
			cfg,
			userRepo,
			tokenRepo,
			otpRepo,
			jwtService,
			oauthService,
			emailService,
			otpService,
			encryptionService,
		)

		ctx := context.Background()
		err := authUseCase.SendEmailOTP(ctx, "user@example.com")
		if err == nil {
			t.Error("SendEmailOTP() expected error when email service fails, got nil")
		}
	})
}

// TestAuthUseCase_VerifyEmailOTP tests the VerifyEmailOTP use case
func TestAuthUseCase_VerifyEmailOTP(t *testing.T) {
	cfg := &config.Config{
		OTP: config.OTPConfig{
			Length:        6,
			ExpireMinutes: 5 * time.Minute,
		},
		JWT: config.JWTConfig{
			RefreshTokenExpire: 7 * 24 * time.Hour,
		},
	}

	t.Run("should verify OTP and create new user", func(t *testing.T) {
		userRepo := mocks.NewMockUserRepository()
		tokenRepo := mocks.NewMockTokenRepository()
		otpRepo := mocks.NewMockOTPRepository()
		jwtService := mocks.NewMockJWTService()
		oauthService := mocks.NewMockOAuthService()
		emailService := mocks.NewMockEmailService()
		otpService := mocks.NewMockOTPService()
		encryptionService := mocks.NewMockEncryptionService()

		// Store OTP
		otpRepo.OTPs["hashed-email"] = "123456"

		authUseCase := usecase.NewAuthUseCase(
			cfg,
			userRepo,
			tokenRepo,
			otpRepo,
			jwtService,
			oauthService,
			emailService,
			otpService,
			encryptionService,
		)

		ctx := context.Background()

		tokenPair, user, err := authUseCase.VerifyEmailOTP(ctx, "user@example.com", "123456")
		if err != nil {
			t.Errorf("VerifyEmailOTP() error = %v, want nil", err)
		}
		if tokenPair == nil {
			t.Error("VerifyEmailOTP() returned nil tokenPair")
		}
		if user == nil {
			t.Error("VerifyEmailOTP() returned nil user")
		}
	})

	t.Run("should fail with invalid OTP", func(t *testing.T) {
		userRepo := mocks.NewMockUserRepository()
		tokenRepo := mocks.NewMockTokenRepository()
		otpRepo := mocks.NewMockOTPRepository()
		jwtService := mocks.NewMockJWTService()
		oauthService := mocks.NewMockOAuthService()
		emailService := mocks.NewMockEmailService()
		otpService := mocks.NewMockOTPService()
		encryptionService := mocks.NewMockEncryptionService()

		// Store different OTP
		otpRepo.OTPs["hashed-email"] = "654321"

		authUseCase := usecase.NewAuthUseCase(
			cfg,
			userRepo,
			tokenRepo,
			otpRepo,
			jwtService,
			oauthService,
			emailService,
			otpService,
			encryptionService,
		)

		ctx := context.Background()

		_, _, err := authUseCase.VerifyEmailOTP(ctx, "user@example.com", "123456")
		if err == nil {
			t.Error("VerifyEmailOTP() expected error for invalid OTP, got nil")
		}
	})

	t.Run("should fail when OTP expired", func(t *testing.T) {
		userRepo := mocks.NewMockUserRepository()
		tokenRepo := mocks.NewMockTokenRepository()
		otpRepo := mocks.NewMockOTPRepository()
		jwtService := mocks.NewMockJWTService()
		oauthService := mocks.NewMockOAuthService()
		emailService := mocks.NewMockEmailService()
		otpService := mocks.NewMockOTPService()
		encryptionService := mocks.NewMockEncryptionService()

		// No OTP stored (simulates expired)

		authUseCase := usecase.NewAuthUseCase(
			cfg,
			userRepo,
			tokenRepo,
			otpRepo,
			jwtService,
			oauthService,
			emailService,
			otpService,
			encryptionService,
		)

		ctx := context.Background()

		_, _, err := authUseCase.VerifyEmailOTP(ctx, "user@example.com", "123456")
		if err == nil {
			t.Error("VerifyEmailOTP() expected error for expired OTP, got nil")
		}
	})
}

// TestAuthUseCase_RefreshToken tests the RefreshToken use case
func TestAuthUseCase_RefreshToken(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			RefreshTokenExpire: 7 * 24 * time.Hour,
		},
	}

	t.Run("should refresh token successfully", func(t *testing.T) {
		userRepo := mocks.NewMockUserRepository()
		tokenRepo := mocks.NewMockTokenRepository()
		otpRepo := mocks.NewMockOTPRepository()
		jwtService := mocks.NewMockJWTService()
		oauthService := mocks.NewMockOAuthService()
		emailService := mocks.NewMockEmailService()
		otpService := mocks.NewMockOTPService()
		encryptionService := mocks.NewMockEncryptionService()

		// Create user
		userID := uuid.New()
		user := &entity.User{
			ID:    userID,
			Email: "test@example.com",
			Name:  "Test User",
		}
		userRepo.AddUser(user)

		// Setup JWT claims
		jti := "test-jti"
		jwtService.Claims = &entity.JWTClaims{
			UserID:    userID,
			Email:     "test@example.com",
			TokenType: entity.TokenTypeRefresh,
			JTI:       jti,
		}

		// Store refresh token
		tokenRepo.RefreshTokens[jti] = userID

		authUseCase := usecase.NewAuthUseCase(
			cfg,
			userRepo,
			tokenRepo,
			otpRepo,
			jwtService,
			oauthService,
			emailService,
			otpService,
			encryptionService,
		)

		ctx := context.Background()

		tokenPair, err := authUseCase.RefreshToken(ctx, "mock-refresh-token")
		if err != nil {
			t.Errorf("RefreshToken() error = %v, want nil", err)
		}
		if tokenPair == nil {
			t.Error("RefreshToken() returned nil tokenPair")
		}
	})

	t.Run("should fail with blacklisted token", func(t *testing.T) {
		userRepo := mocks.NewMockUserRepository()
		tokenRepo := mocks.NewMockTokenRepository()
		otpRepo := mocks.NewMockOTPRepository()
		jwtService := mocks.NewMockJWTService()
		oauthService := mocks.NewMockOAuthService()
		emailService := mocks.NewMockEmailService()
		otpService := mocks.NewMockOTPService()
		encryptionService := mocks.NewMockEncryptionService()

		jti := "blacklisted-jti"
		jwtService.Claims = &entity.JWTClaims{
			UserID:    uuid.New(),
			Email:     "test@example.com",
			TokenType: entity.TokenTypeRefresh,
			JTI:       jti,
		}

		// Blacklist token
		tokenRepo.BlacklistedTokens[jti] = true

		authUseCase := usecase.NewAuthUseCase(
			cfg,
			userRepo,
			tokenRepo,
			otpRepo,
			jwtService,
			oauthService,
			emailService,
			otpService,
			encryptionService,
		)

		ctx := context.Background()

		_, err := authUseCase.RefreshToken(ctx, "mock-refresh-token")
		if err == nil {
			t.Error("RefreshToken() expected error for blacklisted token, got nil")
		}
	})
}

// TestAuthUseCase_Logout tests the Logout use case
func TestAuthUseCase_Logout(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			AccessTokenExpire: 15 * time.Minute,
		},
	}

	t.Run("should logout successfully", func(t *testing.T) {
		userRepo := mocks.NewMockUserRepository()
		tokenRepo := mocks.NewMockTokenRepository()
		otpRepo := mocks.NewMockOTPRepository()
		jwtService := mocks.NewMockJWTService()
		oauthService := mocks.NewMockOAuthService()
		emailService := mocks.NewMockEmailService()
		otpService := mocks.NewMockOTPService()
		encryptionService := mocks.NewMockEncryptionService()

		userID := uuid.New()
		jwtService.Claims = &entity.JWTClaims{
			UserID:    userID,
			Email:     "test@example.com",
			TokenType: entity.TokenTypeAccess,
			JTI:       "test-jti",
		}

		authUseCase := usecase.NewAuthUseCase(
			cfg,
			userRepo,
			tokenRepo,
			otpRepo,
			jwtService,
			oauthService,
			emailService,
			otpService,
			encryptionService,
		)

		ctx := context.Background()

		err := authUseCase.Logout(ctx, "mock-access-token")
		if err != nil {
			t.Errorf("Logout() error = %v, want nil", err)
		}
	})
}

// TestAuthUseCase_GetProfile tests the GetProfile use case
func TestAuthUseCase_GetProfile(t *testing.T) {
	cfg := &config.Config{}

	t.Run("should get profile successfully", func(t *testing.T) {
		userRepo := mocks.NewMockUserRepository()
		tokenRepo := mocks.NewMockTokenRepository()
		otpRepo := mocks.NewMockOTPRepository()
		jwtService := mocks.NewMockJWTService()
		oauthService := mocks.NewMockOAuthService()
		emailService := mocks.NewMockEmailService()
		otpService := mocks.NewMockOTPService()
		encryptionService := mocks.NewMockEncryptionService()

		userID := uuid.New()
		user := &entity.User{
			ID:    userID,
			Email: "test@example.com",
			Name:  "Test User",
		}
		userRepo.AddUser(user)

		authUseCase := usecase.NewAuthUseCase(
			cfg,
			userRepo,
			tokenRepo,
			otpRepo,
			jwtService,
			oauthService,
			emailService,
			otpService,
			encryptionService,
		)

		ctx := context.Background()

		result, err := authUseCase.GetProfile(ctx, userID)
		if err != nil {
			t.Errorf("GetProfile() error = %v, want nil", err)
		}
		if result == nil {
			t.Error("GetProfile() returned nil user")
		}
		if result != nil && result.Email != "test@example.com" {
			t.Errorf("GetProfile() user.Email = %v, want test@example.com", result.Email)
		}
	})

	t.Run("should fail for non-existent user", func(t *testing.T) {
		userRepo := mocks.NewMockUserRepository()
		tokenRepo := mocks.NewMockTokenRepository()
		otpRepo := mocks.NewMockOTPRepository()
		jwtService := mocks.NewMockJWTService()
		oauthService := mocks.NewMockOAuthService()
		emailService := mocks.NewMockEmailService()
		otpService := mocks.NewMockOTPService()
		encryptionService := mocks.NewMockEncryptionService()

		authUseCase := usecase.NewAuthUseCase(
			cfg,
			userRepo,
			tokenRepo,
			otpRepo,
			jwtService,
			oauthService,
			emailService,
			otpService,
			encryptionService,
		)

		ctx := context.Background()

		_, err := authUseCase.GetProfile(ctx, uuid.New())
		if err == nil {
			t.Error("GetProfile() expected error for non-existent user, got nil")
		}
	})
}

// TestAuthUseCase_UpdateProfile tests the UpdateProfile use case
func TestAuthUseCase_UpdateProfile(t *testing.T) {
	cfg := &config.Config{}

	t.Run("should update profile successfully", func(t *testing.T) {
		userRepo := mocks.NewMockUserRepository()
		tokenRepo := mocks.NewMockTokenRepository()
		otpRepo := mocks.NewMockOTPRepository()
		jwtService := mocks.NewMockJWTService()
		oauthService := mocks.NewMockOAuthService()
		emailService := mocks.NewMockEmailService()
		otpService := mocks.NewMockOTPService()
		encryptionService := mocks.NewMockEncryptionService()

		userID := uuid.New()
		user := &entity.User{
			ID:    userID,
			Email: "test@example.com",
			Name:  "Test User",
		}
		userRepo.AddUser(user)

		authUseCase := usecase.NewAuthUseCase(
			cfg,
			userRepo,
			tokenRepo,
			otpRepo,
			jwtService,
			oauthService,
			emailService,
			otpService,
			encryptionService,
		)

		ctx := context.Background()

		result, err := authUseCase.UpdateProfile(ctx, userID, "New Name", "https://example.com/new-pic.jpg")
		if err != nil {
			t.Errorf("UpdateProfile() error = %v, want nil", err)
		}
		if result == nil {
			t.Error("UpdateProfile() returned nil user")
		}
		if result != nil && result.Name != "New Name" {
			t.Errorf("UpdateProfile() user.Name = %v, want New Name", result.Name)
		}
		if result != nil && result.Picture != "https://example.com/new-pic.jpg" {
			t.Errorf("UpdateProfile() user.Picture = %v, want https://example.com/new-pic.jpg", result.Picture)
		}
	})
}

// TestAuthUseCase_ValidateToken tests the ValidateToken use case
func TestAuthUseCase_ValidateToken(t *testing.T) {
	cfg := &config.Config{}

	t.Run("should validate token successfully", func(t *testing.T) {
		userRepo := mocks.NewMockUserRepository()
		tokenRepo := mocks.NewMockTokenRepository()
		otpRepo := mocks.NewMockOTPRepository()
		jwtService := mocks.NewMockJWTService()
		oauthService := mocks.NewMockOAuthService()
		emailService := mocks.NewMockEmailService()
		otpService := mocks.NewMockOTPService()
		encryptionService := mocks.NewMockEncryptionService()

		userID := uuid.New()
		jwtService.Claims = &entity.JWTClaims{
			UserID:    userID,
			Email:     "test@example.com",
			TokenType: entity.TokenTypeAccess,
			JTI:       "valid-jti",
		}

		authUseCase := usecase.NewAuthUseCase(
			cfg,
			userRepo,
			tokenRepo,
			otpRepo,
			jwtService,
			oauthService,
			emailService,
			otpService,
			encryptionService,
		)

		ctx := context.Background()

		claims, err := authUseCase.ValidateToken(ctx, "valid-token")
		if err != nil {
			t.Errorf("ValidateToken() error = %v, want nil", err)
		}
		if claims == nil {
			t.Error("ValidateToken() returned nil claims")
		}
		if claims != nil && claims.UserID != userID {
			t.Errorf("ValidateToken() claims.UserID = %v, want %v", claims.UserID, userID)
		}
	})

	t.Run("should fail for blacklisted token", func(t *testing.T) {
		userRepo := mocks.NewMockUserRepository()
		tokenRepo := mocks.NewMockTokenRepository()
		otpRepo := mocks.NewMockOTPRepository()
		jwtService := mocks.NewMockJWTService()
		oauthService := mocks.NewMockOAuthService()
		emailService := mocks.NewMockEmailService()
		otpService := mocks.NewMockOTPService()
		encryptionService := mocks.NewMockEncryptionService()

		jti := "blacklisted-jti"
		jwtService.Claims = &entity.JWTClaims{
			UserID:    uuid.New(),
			Email:     "test@example.com",
			TokenType: entity.TokenTypeAccess,
			JTI:       jti,
		}
		tokenRepo.BlacklistedTokens[jti] = true

		authUseCase := usecase.NewAuthUseCase(
			cfg,
			userRepo,
			tokenRepo,
			otpRepo,
			jwtService,
			oauthService,
			emailService,
			otpService,
			encryptionService,
		)

		ctx := context.Background()

		_, err := authUseCase.ValidateToken(ctx, "blacklisted-token")
		if err == nil {
			t.Error("ValidateToken() expected error for blacklisted token, got nil")
		}
	})
}

// Helper to check service interface compliance
var _ service.AuthUseCase = (*usecase.AuthUseCase)(nil)
