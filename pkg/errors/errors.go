// Package errors provides custom error types for the application.
package errors

import (
	"fmt"
)

// ErrorCode represents specific error types
type ErrorCode string

const (
	// Authentication errors
	ErrCodeUnauthorized ErrorCode = "UNAUTHORIZED"
	ErrCodeInvalidToken ErrorCode = "INVALID_TOKEN"
	ErrCodeTokenExpired ErrorCode = "TOKEN_EXPIRED"
	ErrCodeTokenRevoked ErrorCode = "TOKEN_REVOKED"

	// OAuth errors
	ErrCodeOAuthFailed  ErrorCode = "OAUTH_FAILED"
	ErrCodeInvalidState ErrorCode = "INVALID_OAUTH_STATE"

	// OTP errors
	ErrCodeOTPExpired     ErrorCode = "OTP_EXPIRED"
	ErrCodeOTPInvalid     ErrorCode = "OTP_INVALID"
	ErrCodeOTPMaxAttempts ErrorCode = "OTP_MAX_ATTEMPTS"

	// User errors
	ErrCodeUserNotFound ErrorCode = "USER_NOT_FOUND"
	ErrCodeUserExists   ErrorCode = "USER_EXISTS"

	// Validation errors
	ErrCodeValidation ErrorCode = "VALIDATION_ERROR"
	ErrCodeBadRequest ErrorCode = "BAD_REQUEST"

	// Internal errors
	ErrCodeInternal ErrorCode = "INTERNAL_ERROR"
	ErrCodeDatabase ErrorCode = "DATABASE_ERROR"
	ErrCodeRedis    ErrorCode = "REDIS_ERROR"
)

// AppError represents an application error
type AppError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Err     error     `json:"-"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *AppError) Unwrap() error {
	return e.Err
}

// New creates a new AppError
func New(code ErrorCode, message string) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
	}
}

// Wrap wraps an error with AppError
func Wrap(code ErrorCode, message string, err error) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// Common error constructors

// ErrUnauthorized creates an unauthorized error
func ErrUnauthorized(message string) *AppError {
	return New(ErrCodeUnauthorized, message)
}

// ErrInvalidToken creates an invalid token error
func ErrInvalidToken(message string) *AppError {
	return New(ErrCodeInvalidToken, message)
}

// ErrTokenExpired creates a token expired error
func ErrTokenExpired() *AppError {
	return New(ErrCodeTokenExpired, "Token has expired")
}

// ErrUserNotFound creates a user not found error
func ErrUserNotFound() *AppError {
	return New(ErrCodeUserNotFound, "User not found")
}

// ErrValidation creates a validation error
func ErrValidation(message string) *AppError {
	return New(ErrCodeValidation, message)
}

// ErrInternal creates an internal error
func ErrInternal(message string, err error) *AppError {
	return Wrap(ErrCodeInternal, message, err)
}

// ErrOTPExpired creates an OTP expired error
func ErrOTPExpired() *AppError {
	return New(ErrCodeOTPExpired, "OTP has expired")
}

// ErrOTPInvalid creates an invalid OTP error
func ErrOTPInvalid() *AppError {
	return New(ErrCodeOTPInvalid, "Invalid OTP")
}

// ErrOTPMaxAttempts creates a max OTP attempts error
func ErrOTPMaxAttempts() *AppError {
	return New(ErrCodeOTPMaxAttempts, "Maximum OTP attempts exceeded")
}
