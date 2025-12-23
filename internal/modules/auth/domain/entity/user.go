// Package entity defines domain entities for the auth module.
package entity

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system
type User struct {
	ID                          uuid.UUID  `json:"id"`
	Email                       string     `json:"email"`
	Name                        string     `json:"name"`
	Picture                     string     `json:"picture,omitempty"`
	GoogleID                    *string    `json:"-"` // Never expose Google ID
	PasswordHash                *string    `json:"-"` // For email-based login (hashed)
	GoogleRefreshTokenEncrypted *string    `json:"-"` // Encrypted Google refresh token
	EmailVerified               bool       `json:"email_verified"`
	CreatedAt                   time.Time  `json:"created_at"`
	UpdatedAt                   time.Time  `json:"updated_at"`
	LastLoginAt                 *time.Time `json:"last_login_at,omitempty"`
}

// NewUser creates a new user with default values
func NewUser(email, name string) *User {
	now := time.Now().UTC()
	return &User{
		ID:            uuid.New(),
		Email:         email,
		Name:          name,
		EmailVerified: false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

// NewGoogleUser creates a new user from Google OAuth data
func NewGoogleUser(email, name, picture, googleID string) *User {
	user := NewUser(email, name)
	user.GoogleID = &googleID
	user.Picture = picture
	user.EmailVerified = true // Google already verified the email
	return user
}

// UpdateGoogleTokens updates the Google OAuth tokens
func (u *User) UpdateGoogleTokens(encryptedRefreshToken string) {
	u.GoogleRefreshTokenEncrypted = &encryptedRefreshToken
	u.UpdatedAt = time.Now().UTC()
}

// UpdateLastLogin updates the last login timestamp
func (u *User) UpdateLastLogin() {
	now := time.Now().UTC()
	u.LastLoginAt = &now
	u.UpdatedAt = now
}

// UpdateProfile updates user profile fields
func (u *User) UpdateProfile(name, picture string) {
	if name != "" {
		u.Name = name
	}
	if picture != "" {
		u.Picture = picture
	}
	u.UpdatedAt = time.Now().UTC()
}

// HasGoogleLinked returns true if user has Google account linked
func (u *User) HasGoogleLinked() bool {
	return u.GoogleID != nil && *u.GoogleID != ""
}

// HasPassword returns true if user has password set (email login)
func (u *User) HasPassword() bool {
	return u.PasswordHash != nil && *u.PasswordHash != ""
}
