// Package entity defines domain entities for the auth module.
package entity

import (
	"time"

	"github.com/google/uuid"
)

// TokenType represents the type of token
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

// TokenPair represents a pair of access and refresh tokens
type TokenPair struct {
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	TokenType             string    `json:"token_type"`
}

// NewTokenPair creates a new token pair
func NewTokenPair(accessToken, refreshToken string, accessExp, refreshExp time.Time) *TokenPair {
	return &TokenPair{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  accessExp,
		RefreshTokenExpiresAt: refreshExp,
		TokenType:             "Bearer",
	}
}

// JWTClaims represents the claims in the JWT token
type JWTClaims struct {
	UserID    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	TokenType TokenType `json:"token_type"`
	JTI       string    `json:"jti"` // JWT ID for revocation
}

// GoogleToken represents Google OAuth tokens
type GoogleToken struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresAt    time.Time
}

// OTPToken represents an OTP for email verification
type OTPToken struct {
	HashedEmail string    // Bcrypt hashed email as key
	Code        string    // 6-digit OTP code
	ExpiresAt   time.Time // Expiration time
	Attempts    int       // Number of verification attempts
}

// MaxOTPAttempts is the maximum number of OTP verification attempts
const MaxOTPAttempts = 3

// NewOTPToken creates a new OTP token
func NewOTPToken(hashedEmail, code string, expireMinutes time.Duration) *OTPToken {
	return &OTPToken{
		HashedEmail: hashedEmail,
		Code:        code,
		ExpiresAt:   time.Now().UTC().Add(expireMinutes),
		Attempts:    0,
	}
}

// IsExpired checks if the OTP has expired
func (o *OTPToken) IsExpired() bool {
	return time.Now().UTC().After(o.ExpiresAt)
}

// CanAttempt checks if more verification attempts are allowed
func (o *OTPToken) CanAttempt() bool {
	return o.Attempts < MaxOTPAttempts
}

// IncrementAttempts increments the attempt counter
func (o *OTPToken) IncrementAttempts() {
	o.Attempts++
}

// Verify checks if the provided code matches
func (o *OTPToken) Verify(code string) bool {
	return o.Code == code
}

// OAuthState represents the state parameter for OAuth flow
type OAuthState struct {
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewOAuthState creates a new OAuth state with 10-minute expiry
func NewOAuthState() *OAuthState {
	now := time.Now().UTC()
	return &OAuthState{
		State:     uuid.New().String(),
		CreatedAt: now,
		ExpiresAt: now.Add(10 * time.Minute),
	}
}

// IsExpired checks if the OAuth state has expired
func (s *OAuthState) IsExpired() bool {
	return time.Now().UTC().After(s.ExpiresAt)
}
