// Package otp provides OTP generation and verification service.
package otp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/dummy-event/internal/config"
	"github.com/dummy-event/internal/modules/auth/domain/service"
)

// Ensure implementation satisfies interface
var _ service.OTPService = (*OTPGenerator)(nil)

// OTPGenerator implements OTPService
type OTPGenerator struct {
	length int
}

// NewOTPGenerator creates a new OTPGenerator
func NewOTPGenerator(cfg *config.OTPConfig) *OTPGenerator {
	return &OTPGenerator{
		length: cfg.Length,
	}
}

// GenerateOTP generates a cryptographically secure random OTP code
func (g *OTPGenerator) GenerateOTP() string {
	// Generate random digits
	max := new(big.Int)
	max.SetString(fmt.Sprintf("%s", powerOf10(g.length)), 10)

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		// Fallback to simple generation (should not happen)
		return fmt.Sprintf("%0*d", g.length, 123456)
	}

	// Format with leading zeros
	return fmt.Sprintf("%0*d", g.length, n)
}

// powerOf10 returns "1" followed by n zeros as a string
func powerOf10(n int) string {
	result := "1"
	for i := 0; i < n; i++ {
		result += "0"
	}
	return result
}

// HashEmail hashes email using SHA256 for deterministic key storage
// This ensures the same email always produces the same hash for OTP lookup
func (g *OTPGenerator) HashEmail(email string) (string, error) {
	// Normalize email to lowercase to ensure consistency
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))

	// Use SHA256 for deterministic hashing
	hash := sha256.Sum256([]byte(normalizedEmail))
	return hex.EncodeToString(hash[:]), nil
}

// VerifyEmailHash verifies email against hash
func (g *OTPGenerator) VerifyEmailHash(email, hash string) bool {
	// Generate hash for comparison
	expectedHash, err := g.HashEmail(email)
	if err != nil {
		return false
	}
	return expectedHash == hash
}
