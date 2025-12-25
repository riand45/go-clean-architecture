// Package tests contains unit tests for encryption service.
package tests

import (
	"testing"

	"github.com/dummy-event/internal/modules/auth/infrastructure/encryption"
)

func TestAESEncryptionService(t *testing.T) {
	// Create a test key (32 bytes for AES-256)
	testKey := []byte("12345678901234567890123456789012")

	t.Run("should encrypt and decrypt successfully", func(t *testing.T) {
		service, err := encryption.NewAESEncryptionServiceWithKey(testKey)
		if err != nil {
			t.Fatalf("NewAESEncryptionServiceWithKey() error = %v", err)
		}

		plaintext := "Hello, World! This is a secret message."

		encrypted, err := service.Encrypt(plaintext)
		if err != nil {
			t.Errorf("Encrypt() error = %v, want nil", err)
		}
		if encrypted == "" {
			t.Error("Encrypt() returned empty ciphertext")
		}
		if encrypted == plaintext {
			t.Error("Encrypt() returned plaintext unchanged")
		}

		decrypted, err := service.Decrypt(encrypted)
		if err != nil {
			t.Errorf("Decrypt() error = %v, want nil", err)
		}
		if decrypted != plaintext {
			t.Errorf("Decrypt() = %v, want %v", decrypted, plaintext)
		}
	})

	t.Run("should handle empty string", func(t *testing.T) {
		service, _ := encryption.NewAESEncryptionServiceWithKey(testKey)

		encrypted, err := service.Encrypt("")
		if err != nil {
			t.Errorf("Encrypt() error = %v for empty string", err)
		}
		if encrypted != "" {
			t.Error("Encrypt() should return empty for empty input")
		}

		decrypted, err := service.Decrypt("")
		if err != nil {
			t.Errorf("Decrypt() error = %v for empty string", err)
		}
		if decrypted != "" {
			t.Error("Decrypt() should return empty for empty input")
		}
	})

	t.Run("should generate different ciphertext for same plaintext", func(t *testing.T) {
		service, _ := encryption.NewAESEncryptionServiceWithKey(testKey)

		plaintext := "Same message"
		encrypted1, _ := service.Encrypt(plaintext)
		encrypted2, _ := service.Encrypt(plaintext)

		if encrypted1 == encrypted2 {
			t.Error("Encrypt() should produce different ciphertext due to random nonce")
		}

		// Both should decrypt to same plaintext
		decrypted1, _ := service.Decrypt(encrypted1)
		decrypted2, _ := service.Decrypt(encrypted2)

		if decrypted1 != plaintext || decrypted2 != plaintext {
			t.Error("Decrypt() should produce same plaintext for both ciphertexts")
		}
	})

	t.Run("should fail with invalid key length", func(t *testing.T) {
		shortKey := []byte("short")
		_, err := encryption.NewAESEncryptionServiceWithKey(shortKey)
		if err == nil {
			t.Error("NewAESEncryptionServiceWithKey() should fail with short key")
		}
	})

	t.Run("should fail to decrypt invalid ciphertext", func(t *testing.T) {
		service, _ := encryption.NewAESEncryptionServiceWithKey(testKey)

		_, err := service.Decrypt("invalid-base64!")
		if err == nil {
			t.Error("Decrypt() should fail with invalid base64")
		}

		// Valid base64 but invalid ciphertext
		_, err = service.Decrypt("aW52YWxpZGNpcGhlcnRleHQ=")
		if err == nil {
			t.Error("Decrypt() should fail with invalid ciphertext")
		}
	})
}

func TestGenerateKey(t *testing.T) {
	t.Run("should generate valid key", func(t *testing.T) {
		key1, err := encryption.GenerateKey()
		if err != nil {
			t.Errorf("GenerateKey() error = %v", err)
		}
		if key1 == "" {
			t.Error("GenerateKey() returned empty key")
		}

		// Generate another key and ensure they're different
		key2, _ := encryption.GenerateKey()
		if key1 == key2 {
			t.Error("GenerateKey() should produce different keys")
		}
	})
}
