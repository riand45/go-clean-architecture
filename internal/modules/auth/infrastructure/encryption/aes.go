// Package encryption provides AES-256-GCM encryption service for sensitive data.
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/dummy-event/internal/modules/auth/domain/service"
)

// Ensure implementation satisfies interface
var _ service.EncryptionService = (*AESEncryptionService)(nil)

// AESEncryptionService implements EncryptionService using AES-256-GCM
type AESEncryptionService struct {
	key []byte
}

// NewAESEncryptionService creates a new AESEncryptionService
// Key must be 32 bytes for AES-256
func NewAESEncryptionService() (*AESEncryptionService, error) {
	// Get encryption key from environment
	keyStr := os.Getenv("ENCRYPTION_KEY")
	if keyStr == "" {
		// Generate a random key for development (not recommended for production)
		// In production, this should always be set via environment variable
		return nil, fmt.Errorf("ENCRYPTION_KEY environment variable is required")
	}

	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid ENCRYPTION_KEY format: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("ENCRYPTION_KEY must be 32 bytes (got %d)", len(key))
	}

	return &AESEncryptionService{key: key}, nil
}

// NewAESEncryptionServiceWithKey creates a new AESEncryptionService with provided key
func NewAESEncryptionServiceWithKey(key []byte) (*AESEncryptionService, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256 (got %d)", len(key))
	}
	return &AESEncryptionService{key: key}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM
func (s *AESEncryptionService) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and prepend nonce
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// Encode to base64 for storage
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES-256-GCM
func (s *AESEncryptionService) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	// Decode from base64
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, cipherData := data[:nonceSize], data[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// GenerateKey generates a random 32-byte key for AES-256
// This can be used to generate a new ENCRYPTION_KEY
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("failed to generate key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
