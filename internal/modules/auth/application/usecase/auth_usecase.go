// Package usecase implements authentication business logic.
package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dummy-event/internal/config"
	"github.com/dummy-event/internal/modules/auth/domain/entity"
	"github.com/dummy-event/internal/modules/auth/domain/repository"
	"github.com/dummy-event/internal/modules/auth/domain/service"
)

// Ensure implementation satisfies interface
var _ service.AuthUseCase = (*AuthUseCase)(nil)

// AuthUseCase implements the main authentication use case
type AuthUseCase struct {
	cfg               *config.Config
	userRepo          repository.UserRepository
	tokenRepo         repository.TokenRepository
	otpRepo           repository.OTPRepository
	jwtService        service.JWTService
	oauthService      service.OAuthService
	emailService      service.EmailService
	otpService        service.OTPService
	encryptionService service.EncryptionService
}

// NewAuthUseCase creates a new AuthUseCase
func NewAuthUseCase(
	cfg *config.Config,
	userRepo repository.UserRepository,
	tokenRepo repository.TokenRepository,
	otpRepo repository.OTPRepository,
	jwtService service.JWTService,
	oauthService service.OAuthService,
	emailService service.EmailService,
	otpService service.OTPService,
	encryptionService service.EncryptionService,
) *AuthUseCase {
	return &AuthUseCase{
		cfg:               cfg,
		userRepo:          userRepo,
		tokenRepo:         tokenRepo,
		otpRepo:           otpRepo,
		jwtService:        jwtService,
		oauthService:      oauthService,
		emailService:      emailService,
		otpService:        otpService,
		encryptionService: encryptionService,
	}
}

// ================================
// Google OAuth Flow
// ================================

// GetGoogleAuthURL generates the Google OAuth authorization URL
func (uc *AuthUseCase) GetGoogleAuthURL(ctx context.Context) (string, error) {
	// Generate state for CSRF protection
	state := entity.NewOAuthState()

	// Store state in Redis with 10-minute expiry
	if err := uc.tokenRepo.StoreOAuthState(ctx, state.State, 10*time.Minute); err != nil {
		return "", fmt.Errorf("failed to store OAuth state: %w", err)
	}

	// Generate authorization URL
	authURL := uc.oauthService.GetAuthURL(state.State)

	return authURL, nil
}

// HandleGoogleCallback handles the Google OAuth callback
func (uc *AuthUseCase) HandleGoogleCallback(ctx context.Context, code, state string) (*entity.TokenPair, *entity.User, error) {
	// Validate OAuth state (CSRF protection)
	valid, err := uc.tokenRepo.ValidateOAuthState(ctx, state)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate OAuth state: %w", err)
	}
	if !valid {
		return nil, nil, fmt.Errorf("invalid or expired OAuth state")
	}

	// Exchange authorization code for tokens
	googleToken, err := uc.oauthService.ExchangeCode(ctx, code)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	// Get user info from Google
	userInfo, err := uc.oauthService.GetUserInfo(ctx, googleToken.AccessToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user info from Google: %w", err)
	}

	// Validate email is verified
	if !userInfo.VerifiedEmail {
		return nil, nil, fmt.Errorf("email not verified with Google")
	}

	// Find or create user
	user, isNewUser, err := uc.findOrCreateGoogleUser(ctx, userInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find or create user: %w", err)
	}

	// Store Google access token in Redis with TTL
	tokenExpiry := time.Until(googleToken.ExpiresAt)
	if tokenExpiry > 0 {
		if err := uc.tokenRepo.StoreGoogleAccessToken(ctx, user.ID, googleToken.AccessToken, tokenExpiry); err != nil {
			// Log error but don't fail the login
			fmt.Printf("Warning: failed to store Google access token: %v\n", err)
		}
	}

	// Store encrypted Google refresh token in database (if provided)
	if googleToken.RefreshToken != "" {
		encryptedRefreshToken, err := uc.encryptionService.Encrypt(googleToken.RefreshToken)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encrypt refresh token: %w", err)
		}
		if err := uc.userRepo.UpdateGoogleRefreshToken(ctx, user.ID, encryptedRefreshToken); err != nil {
			// Log error but don't fail the login
			fmt.Printf("Warning: failed to store Google refresh token: %v\n", err)
		}
	}

	// Update last login
	if err := uc.userRepo.UpdateLastLogin(ctx, user.ID); err != nil {
		// Log error but don't fail
		fmt.Printf("Warning: failed to update last login: %v\n", err)
	}

	// Generate application JWT tokens
	tokenPair, err := uc.jwtService.GenerateTokenPair(ctx, user)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate JWT tokens: %w", err)
	}

	// Store refresh token JTI in Redis for lookup
	refreshClaims, _ := uc.jwtService.ValidateRefreshToken(ctx, tokenPair.RefreshToken)
	if refreshClaims != nil {
		if err := uc.tokenRepo.StoreRefreshToken(ctx, refreshClaims.JTI, user.ID, uc.cfg.JWT.RefreshTokenExpire); err != nil {
			// Log error but don't fail
			fmt.Printf("Warning: failed to store refresh token: %v\n", err)
		}
	}

	// Send welcome email for new users (async, don't block)
	if isNewUser {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = uc.emailService.SendWelcome(ctx, user.Email, user.Name)
		}()
	}

	return tokenPair, user, nil
}

// findOrCreateGoogleUser finds existing user or creates a new one
func (uc *AuthUseCase) findOrCreateGoogleUser(ctx context.Context, userInfo *service.GoogleUserInfo) (*entity.User, bool, error) {
	// First, try to find by Google ID
	user, err := uc.userRepo.FindByGoogleID(ctx, userInfo.ID)
	if err != nil {
		return nil, false, err
	}
	if user != nil {
		// Update profile if changed
		user.UpdateProfile(userInfo.Name, userInfo.Picture)
		if err := uc.userRepo.Update(ctx, user); err != nil {
			// Log warning but continue
			fmt.Printf("Warning: failed to update user profile: %v\n", err)
		}
		return user, false, nil
	}

	// Try to find by email
	user, err = uc.userRepo.FindByEmail(ctx, userInfo.Email)
	if err != nil {
		return nil, false, err
	}
	if user != nil {
		// Link Google account to existing user
		googleID := userInfo.ID
		user.GoogleID = &googleID
		user.UpdateProfile(userInfo.Name, userInfo.Picture)
		user.EmailVerified = true
		if err := uc.userRepo.Update(ctx, user); err != nil {
			return nil, false, fmt.Errorf("failed to link Google account: %w", err)
		}
		return user, false, nil
	}

	// Create new user
	user = entity.NewGoogleUser(userInfo.Email, userInfo.Name, userInfo.Picture, userInfo.ID)
	if err := uc.userRepo.Create(ctx, user); err != nil {
		return nil, false, fmt.Errorf("failed to create user: %w", err)
	}

	return user, true, nil
}

// ================================
// Email OTP Flow
// ================================

// SendEmailOTP sends an OTP to the specified email
func (uc *AuthUseCase) SendEmailOTP(ctx context.Context, email string) error {
	// Generate OTP
	otpCode := uc.otpService.GenerateOTP()

	// Hash email for secure key storage
	hashedEmail, err := uc.otpService.HashEmail(email)
	if err != nil {
		return fmt.Errorf("failed to hash email: %w", err)
	}

	// Store OTP in Redis with TTL
	if err := uc.otpRepo.StoreOTP(ctx, hashedEmail, otpCode, uc.cfg.OTP.ExpireMinutes); err != nil {
		return fmt.Errorf("failed to store OTP: %w", err)
	}

	// Reset attempt counter
	if err := uc.otpRepo.ResetOTPAttempts(ctx, hashedEmail); err != nil {
		// Log warning but continue
		fmt.Printf("Warning: failed to reset OTP attempts: %v\n", err)
	}

	// Send OTP via email
	if err := uc.emailService.SendOTP(ctx, email, otpCode); err != nil {
		// Clean up stored OTP on email failure
		_ = uc.otpRepo.DeleteOTP(ctx, hashedEmail)
		return fmt.Errorf("failed to send OTP email: %w", err)
	}

	return nil
}

// VerifyEmailOTP verifies the OTP and logs in the user
func (uc *AuthUseCase) VerifyEmailOTP(ctx context.Context, email, otp string) (*entity.TokenPair, *entity.User, error) {
	// Hash email to get the key
	hashedEmail, err := uc.otpService.HashEmail(email)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash email: %w", err)
	}

	// Check attempt count
	attempts, err := uc.otpRepo.IncrementOTPAttempts(ctx, hashedEmail, entity.MaxOTPAttempts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to check OTP attempts: %w", err)
	}
	if attempts > entity.MaxOTPAttempts {
		// Delete OTP after max attempts
		_ = uc.otpRepo.DeleteOTP(ctx, hashedEmail)
		return nil, nil, fmt.Errorf("maximum OTP attempts exceeded")
	}

	// Get stored OTP
	storedOTP, err := uc.otpRepo.GetOTP(ctx, hashedEmail)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve OTP: %w", err)
	}
	if storedOTP == "" {
		return nil, nil, fmt.Errorf("OTP expired or not found")
	}

	// Verify OTP
	if storedOTP != otp {
		return nil, nil, fmt.Errorf("invalid OTP")
	}

	// Delete OTP after successful verification
	if err := uc.otpRepo.DeleteOTP(ctx, hashedEmail); err != nil {
		// Log warning but continue
		fmt.Printf("Warning: failed to delete OTP: %v\n", err)
	}

	// Reset attempts
	_ = uc.otpRepo.ResetOTPAttempts(ctx, hashedEmail)

	// Find or create user
	user, isNewUser, err := uc.findOrCreateEmailUser(ctx, email)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find or create user: %w", err)
	}

	// Update last login
	if err := uc.userRepo.UpdateLastLogin(ctx, user.ID); err != nil {
		fmt.Printf("Warning: failed to update last login: %v\n", err)
	}

	// Generate JWT tokens
	tokenPair, err := uc.jwtService.GenerateTokenPair(ctx, user)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate JWT tokens: %w", err)
	}

	// Store refresh token JTI in Redis
	refreshClaims, _ := uc.jwtService.ValidateRefreshToken(ctx, tokenPair.RefreshToken)
	if refreshClaims != nil {
		if err := uc.tokenRepo.StoreRefreshToken(ctx, refreshClaims.JTI, user.ID, uc.cfg.JWT.RefreshTokenExpire); err != nil {
			fmt.Printf("Warning: failed to store refresh token: %v\n", err)
		}
	}

	// Send welcome email for new users
	if isNewUser {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = uc.emailService.SendWelcome(ctx, user.Email, user.Name)
		}()
	}

	return tokenPair, user, nil
}

// findOrCreateEmailUser finds existing user or creates a new one
func (uc *AuthUseCase) findOrCreateEmailUser(ctx context.Context, email string) (*entity.User, bool, error) {
	// Try to find by email
	user, err := uc.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, false, err
	}
	if user != nil {
		// Mark email as verified
		if !user.EmailVerified {
			user.EmailVerified = true
			if err := uc.userRepo.Update(ctx, user); err != nil {
				fmt.Printf("Warning: failed to update email verified status: %v\n", err)
			}
		}
		return user, false, nil
	}

	// Create new user (use email prefix as name)
	name := email
	if atIndex := len(email); atIndex > 0 {
		for i, c := range email {
			if c == '@' {
				name = email[:i]
				break
			}
		}
	}

	user = entity.NewUser(email, name)
	user.EmailVerified = true
	if err := uc.userRepo.Create(ctx, user); err != nil {
		return nil, false, fmt.Errorf("failed to create user: %w", err)
	}

	return user, true, nil
}

// ================================
// Token Management
// ================================

// RefreshToken exchanges a refresh token for a new token pair
func (uc *AuthUseCase) RefreshToken(ctx context.Context, refreshToken string) (*entity.TokenPair, error) {
	// Validate refresh token
	claims, err := uc.jwtService.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Check if token is blacklisted
	isBlacklisted, err := uc.tokenRepo.IsTokenBlacklisted(ctx, claims.JTI)
	if err != nil {
		return nil, fmt.Errorf("failed to check token blacklist: %w", err)
	}
	if isBlacklisted {
		return nil, fmt.Errorf("refresh token has been revoked")
	}

	// Verify token exists in Redis
	storedUserID, err := uc.tokenRepo.GetRefreshTokenUserID(ctx, claims.JTI)
	if err != nil {
		return nil, fmt.Errorf("refresh token not found or expired: %w", err)
	}
	if storedUserID != claims.UserID {
		return nil, fmt.Errorf("token user ID mismatch")
	}

	// Get user
	user, err := uc.userRepo.FindByID(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Delete old refresh token (token rotation)
	if err := uc.tokenRepo.DeleteRefreshToken(ctx, claims.JTI); err != nil {
		fmt.Printf("Warning: failed to delete old refresh token: %v\n", err)
	}

	// Generate new token pair
	newTokenPair, err := uc.jwtService.GenerateTokenPair(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new tokens: %w", err)
	}

	// Store new refresh token JTI
	newRefreshClaims, _ := uc.jwtService.ValidateRefreshToken(ctx, newTokenPair.RefreshToken)
	if newRefreshClaims != nil {
		if err := uc.tokenRepo.StoreRefreshToken(ctx, newRefreshClaims.JTI, user.ID, uc.cfg.JWT.RefreshTokenExpire); err != nil {
			fmt.Printf("Warning: failed to store new refresh token: %v\n", err)
		}
	}

	return newTokenPair, nil
}

// Logout revokes the current session tokens
func (uc *AuthUseCase) Logout(ctx context.Context, accessToken string) error {
	// Extract JTI from access token
	accessJTI, err := uc.jwtService.ExtractJTI(accessToken)
	if err != nil {
		return fmt.Errorf("failed to extract token ID: %w", err)
	}

	// Validate access token to get claims
	claims, err := uc.jwtService.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		// Token might be expired, but we still want to blacklist it
		// Extract claims without validation for blacklisting
	} else {
		// Delete Google access token from Redis
		if err := uc.tokenRepo.DeleteGoogleAccessToken(ctx, claims.UserID); err != nil {
			fmt.Printf("Warning: failed to delete Google access token: %v\n", err)
		}
	}

	// Blacklist access token (use remaining time or default 15 minutes)
	if err := uc.tokenRepo.BlacklistToken(ctx, accessJTI, uc.cfg.JWT.AccessTokenExpire); err != nil {
		fmt.Printf("Warning: failed to blacklist access token: %v\n", err)
	}

	return nil
}

// ValidateToken validates an access token
func (uc *AuthUseCase) ValidateToken(ctx context.Context, accessToken string) (*entity.JWTClaims, error) {
	// Validate token
	claims, err := uc.jwtService.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	// Check if token is blacklisted
	isBlacklisted, err := uc.tokenRepo.IsTokenBlacklisted(ctx, claims.JTI)
	if err != nil {
		return nil, fmt.Errorf("failed to check token blacklist: %w", err)
	}
	if isBlacklisted {
		return nil, fmt.Errorf("token has been revoked")
	}

	return claims, nil
}

// ================================
// Profile Management
// ================================

// GetProfile retrieves user profile by ID
func (uc *AuthUseCase) GetProfile(ctx context.Context, userID uuid.UUID) (*entity.User, error) {
	user, err := uc.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

// UpdateProfile updates user profile
func (uc *AuthUseCase) UpdateProfile(ctx context.Context, userID uuid.UUID, name, picture string) (*entity.User, error) {
	user, err := uc.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	user.UpdateProfile(name, picture)

	if err := uc.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return user, nil
}
