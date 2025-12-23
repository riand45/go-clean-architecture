// Package dto defines Data Transfer Objects for the auth module.
package dto

import "time"

// ===============================
// Request DTOs
// ===============================

// SendOTPRequest represents a request to send OTP
type SendOTPRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// VerifyOTPRequest represents a request to verify OTP
type VerifyOTPRequest struct {
	Email string `json:"email" validate:"required,email"`
	OTP   string `json:"otp" validate:"required,len=6"`
}

// RefreshTokenRequest represents a request to refresh tokens
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// UpdateProfileRequest represents a request to update user profile
type UpdateProfileRequest struct {
	Name    string `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Picture string `json:"picture,omitempty" validate:"omitempty,url"`
}

// ===============================
// Response DTOs
// ===============================

// AuthResponse represents authentication response with tokens
type AuthResponse struct {
	User      UserResponse  `json:"user"`
	Tokens    TokenResponse `json:"tokens"`
	IsNewUser bool          `json:"is_new_user"`
}

// TokenResponse represents token pair response
type TokenResponse struct {
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	TokenType             string    `json:"token_type"`
}

// UserResponse represents user data response
type UserResponse struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	Name          string     `json:"name"`
	Picture       string     `json:"picture,omitempty"`
	EmailVerified bool       `json:"email_verified"`
	CreatedAt     time.Time  `json:"created_at"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
}

// GoogleAuthURLResponse represents Google OAuth URL response
type GoogleAuthURLResponse struct {
	AuthURL string `json:"auth_url"`
}

// OTPSentResponse represents OTP sent response
type OTPSentResponse struct {
	Message   string    `json:"message"`
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expires_at"`
}

// MessageResponse represents a simple message response
type MessageResponse struct {
	Message string `json:"message"`
}

// ===============================
// Error Response
// ===============================

// ErrorResponse represents an error response
type ErrorResponse struct {
	Success bool        `json:"success"`
	Error   ErrorDetail `json:"error"`
}

// ErrorDetail contains error details
type ErrorDetail struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ===============================
// Success Response Wrapper
// ===============================

// SuccessResponse wraps successful responses
type SuccessResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
}

// NewSuccessResponse creates a new success response
func NewSuccessResponse(data interface{}) SuccessResponse {
	return SuccessResponse{
		Success: true,
		Data:    data,
	}
}

// NewErrorResponse creates a new error response
func NewErrorResponse(code int, message string) ErrorResponse {
	return ErrorResponse{
		Success: false,
		Error: ErrorDetail{
			Code:    code,
			Message: message,
		},
	}
}
