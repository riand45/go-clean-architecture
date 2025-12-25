// Package mocks provides mock implementations for testing.
package mocks

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// MockTokenRepository is a mock implementation of TokenRepository
type MockTokenRepository struct {
	GoogleTokens      map[uuid.UUID]string
	RefreshTokens     map[string]uuid.UUID
	BlacklistedTokens map[string]bool
	OAuthStates       map[string]bool
	StoreErr          error
	GetErr            error
	DeleteErr         error
}

// NewMockTokenRepository creates a new MockTokenRepository
func NewMockTokenRepository() *MockTokenRepository {
	return &MockTokenRepository{
		GoogleTokens:      make(map[uuid.UUID]string),
		RefreshTokens:     make(map[string]uuid.UUID),
		BlacklistedTokens: make(map[string]bool),
		OAuthStates:       make(map[string]bool),
	}
}

func (m *MockTokenRepository) StoreGoogleAccessToken(ctx context.Context, userID uuid.UUID, token string, expiry time.Duration) error {
	if m.StoreErr != nil {
		return m.StoreErr
	}
	m.GoogleTokens[userID] = token
	return nil
}

func (m *MockTokenRepository) GetGoogleAccessToken(ctx context.Context, userID uuid.UUID) (string, error) {
	if m.GetErr != nil {
		return "", m.GetErr
	}
	return m.GoogleTokens[userID], nil
}

func (m *MockTokenRepository) DeleteGoogleAccessToken(ctx context.Context, userID uuid.UUID) error {
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	delete(m.GoogleTokens, userID)
	return nil
}

func (m *MockTokenRepository) StoreRefreshToken(ctx context.Context, jti string, userID uuid.UUID, expiry time.Duration) error {
	if m.StoreErr != nil {
		return m.StoreErr
	}
	m.RefreshTokens[jti] = userID
	return nil
}

func (m *MockTokenRepository) GetRefreshTokenUserID(ctx context.Context, jti string) (uuid.UUID, error) {
	if m.GetErr != nil {
		return uuid.Nil, m.GetErr
	}
	if userID, ok := m.RefreshTokens[jti]; ok {
		return userID, nil
	}
	return uuid.Nil, nil
}

func (m *MockTokenRepository) DeleteRefreshToken(ctx context.Context, jti string) error {
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	delete(m.RefreshTokens, jti)
	return nil
}

func (m *MockTokenRepository) BlacklistToken(ctx context.Context, jti string, expiry time.Duration) error {
	if m.StoreErr != nil {
		return m.StoreErr
	}
	m.BlacklistedTokens[jti] = true
	return nil
}

func (m *MockTokenRepository) IsTokenBlacklisted(ctx context.Context, jti string) (bool, error) {
	if m.GetErr != nil {
		return false, m.GetErr
	}
	return m.BlacklistedTokens[jti], nil
}

func (m *MockTokenRepository) StoreOAuthState(ctx context.Context, state string, expiry time.Duration) error {
	if m.StoreErr != nil {
		return m.StoreErr
	}
	m.OAuthStates[state] = true
	return nil
}

func (m *MockTokenRepository) ValidateOAuthState(ctx context.Context, state string) (bool, error) {
	if m.GetErr != nil {
		return false, m.GetErr
	}
	if m.OAuthStates[state] {
		delete(m.OAuthStates, state)
		return true, nil
	}
	return false, nil
}

// MockOTPRepository is a mock implementation of OTPRepository
type MockOTPRepository struct {
	OTPs      map[string]string
	Attempts  map[string]int
	StoreErr  error
	GetErr    error
	DeleteErr error
}

// NewMockOTPRepository creates a new MockOTPRepository
func NewMockOTPRepository() *MockOTPRepository {
	return &MockOTPRepository{
		OTPs:     make(map[string]string),
		Attempts: make(map[string]int),
	}
}

func (m *MockOTPRepository) StoreOTP(ctx context.Context, hashedEmail, code string, expiry time.Duration) error {
	if m.StoreErr != nil {
		return m.StoreErr
	}
	m.OTPs[hashedEmail] = code
	return nil
}

func (m *MockOTPRepository) GetOTP(ctx context.Context, hashedEmail string) (string, error) {
	if m.GetErr != nil {
		return "", m.GetErr
	}
	return m.OTPs[hashedEmail], nil
}

func (m *MockOTPRepository) DeleteOTP(ctx context.Context, hashedEmail string) error {
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	delete(m.OTPs, hashedEmail)
	return nil
}

func (m *MockOTPRepository) IncrementOTPAttempts(ctx context.Context, hashedEmail string, maxAttempts int) (int, error) {
	if m.GetErr != nil {
		return 0, m.GetErr
	}
	m.Attempts[hashedEmail]++
	return m.Attempts[hashedEmail], nil
}

func (m *MockOTPRepository) ResetOTPAttempts(ctx context.Context, hashedEmail string) error {
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	delete(m.Attempts, hashedEmail)
	return nil
}
