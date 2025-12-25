// Package mocks provides mock implementations for testing.
package mocks

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dummy-event/internal/modules/auth/domain/entity"
	"github.com/dummy-event/internal/modules/auth/domain/service"
)

// MockJWTService is a mock implementation of JWTService
type MockJWTService struct {
	GenerateErr error
	ValidateErr error
	TokenPair   *entity.TokenPair
	Claims      *entity.JWTClaims
}

// NewMockJWTService creates a new MockJWTService
func NewMockJWTService() *MockJWTService {
	return &MockJWTService{}
}

func (m *MockJWTService) GenerateTokenPair(ctx context.Context, user *entity.User) (*entity.TokenPair, error) {
	if m.GenerateErr != nil {
		return nil, m.GenerateErr
	}
	if m.TokenPair != nil {
		return m.TokenPair, nil
	}
	now := time.Now().UTC()
	return &entity.TokenPair{
		AccessToken:           "mock-access-token-" + user.ID.String(),
		RefreshToken:          "mock-refresh-token-" + user.ID.String(),
		AccessTokenExpiresAt:  now.Add(15 * time.Minute),
		RefreshTokenExpiresAt: now.Add(7 * 24 * time.Hour),
		TokenType:             "Bearer",
	}, nil
}

func (m *MockJWTService) ValidateAccessToken(ctx context.Context, tokenString string) (*entity.JWTClaims, error) {
	if m.ValidateErr != nil {
		return nil, m.ValidateErr
	}
	if m.Claims != nil {
		return m.Claims, nil
	}
	return &entity.JWTClaims{
		UserID:    uuid.New(),
		Email:     "test@example.com",
		TokenType: entity.TokenTypeAccess,
		JTI:       uuid.New().String(),
	}, nil
}

func (m *MockJWTService) ValidateRefreshToken(ctx context.Context, tokenString string) (*entity.JWTClaims, error) {
	if m.ValidateErr != nil {
		return nil, m.ValidateErr
	}
	if m.Claims != nil {
		return m.Claims, nil
	}
	return &entity.JWTClaims{
		UserID:    uuid.New(),
		Email:     "test@example.com",
		TokenType: entity.TokenTypeRefresh,
		JTI:       uuid.New().String(),
	}, nil
}

func (m *MockJWTService) ExtractJTI(tokenString string) (string, error) {
	if m.ValidateErr != nil {
		return "", m.ValidateErr
	}
	return "mock-jti-" + uuid.New().String(), nil
}

// MockOAuthService is a mock implementation of OAuthService
type MockOAuthService struct {
	ExchangeErr error
	UserInfoErr error
	GoogleToken *entity.GoogleToken
	UserInfo    *service.GoogleUserInfo
}

// NewMockOAuthService creates a new MockOAuthService
func NewMockOAuthService() *MockOAuthService {
	return &MockOAuthService{}
}

func (m *MockOAuthService) GetAuthURL(state string) string {
	return "https://accounts.google.com/o/oauth2/auth?state=" + state
}

func (m *MockOAuthService) ExchangeCode(ctx context.Context, code string) (*entity.GoogleToken, error) {
	if m.ExchangeErr != nil {
		return nil, m.ExchangeErr
	}
	if m.GoogleToken != nil {
		return m.GoogleToken, nil
	}
	return &entity.GoogleToken{
		AccessToken:  "google-access-token",
		RefreshToken: "google-refresh-token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().UTC().Add(1 * time.Hour),
	}, nil
}

func (m *MockOAuthService) GetUserInfo(ctx context.Context, accessToken string) (*service.GoogleUserInfo, error) {
	if m.UserInfoErr != nil {
		return nil, m.UserInfoErr
	}
	if m.UserInfo != nil {
		return m.UserInfo, nil
	}
	return &service.GoogleUserInfo{
		ID:            "google-user-id-123",
		Email:         "test@example.com",
		VerifiedEmail: true,
		Name:          "Test User",
		GivenName:     "Test",
		FamilyName:    "User",
		Picture:       "https://example.com/picture.jpg",
	}, nil
}

func (m *MockOAuthService) RefreshAccessToken(ctx context.Context, refreshToken string) (*entity.GoogleToken, error) {
	if m.ExchangeErr != nil {
		return nil, m.ExchangeErr
	}
	return &entity.GoogleToken{
		AccessToken:  "new-google-access-token",
		RefreshToken: "",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().UTC().Add(1 * time.Hour),
	}, nil
}

// MockEmailService is a mock implementation of EmailService
type MockEmailService struct {
	SendOTPErr     error
	SendWelcomeErr error
	SentOTPs       map[string]string
	SentWelcomes   []string
}

// NewMockEmailService creates a new MockEmailService
func NewMockEmailService() *MockEmailService {
	return &MockEmailService{
		SentOTPs:     make(map[string]string),
		SentWelcomes: make([]string, 0),
	}
}

func (m *MockEmailService) SendOTP(ctx context.Context, email, otpCode string) error {
	if m.SendOTPErr != nil {
		return m.SendOTPErr
	}
	m.SentOTPs[email] = otpCode
	return nil
}

func (m *MockEmailService) SendWelcome(ctx context.Context, email, name string) error {
	if m.SendWelcomeErr != nil {
		return m.SendWelcomeErr
	}
	m.SentWelcomes = append(m.SentWelcomes, email)
	return nil
}

// MockOTPService is a mock implementation of OTPService
type MockOTPService struct {
	OTPCode     string
	HashedEmail string
	HashErr     error
}

// NewMockOTPService creates a new MockOTPService
func NewMockOTPService() *MockOTPService {
	return &MockOTPService{
		OTPCode:     "123456",
		HashedEmail: "hashed-email",
	}
}

func (m *MockOTPService) GenerateOTP() string {
	return m.OTPCode
}

func (m *MockOTPService) HashEmail(email string) (string, error) {
	if m.HashErr != nil {
		return "", m.HashErr
	}
	return m.HashedEmail, nil
}

func (m *MockOTPService) VerifyEmailHash(email, hash string) bool {
	return hash == m.HashedEmail
}

// MockEncryptionService is a mock implementation of EncryptionService
type MockEncryptionService struct {
	EncryptErr error
	DecryptErr error
}

// NewMockEncryptionService creates a new MockEncryptionService
func NewMockEncryptionService() *MockEncryptionService {
	return &MockEncryptionService{}
}

func (m *MockEncryptionService) Encrypt(plaintext string) (string, error) {
	if m.EncryptErr != nil {
		return "", m.EncryptErr
	}
	return fmt.Sprintf("encrypted:%s", plaintext), nil
}

func (m *MockEncryptionService) Decrypt(ciphertext string) (string, error) {
	if m.DecryptErr != nil {
		return "", m.DecryptErr
	}
	if len(ciphertext) > 10 {
		return ciphertext[10:], nil
	}
	return ciphertext, nil
}
