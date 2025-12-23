// Package jwt provides RSA-based JWT token service.
package jwt

import (
	"context"
	"crypto/rsa"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/dummy-event/internal/config"
	"github.com/dummy-event/internal/modules/auth/domain/entity"
	"github.com/dummy-event/internal/modules/auth/domain/service"
)

// Ensure implementation satisfies interface
var _ service.JWTService = (*RSAJWTService)(nil)

// RSAJWTService implements JWTService using RSA keys
type RSAJWTService struct {
	privateKey         *rsa.PrivateKey
	publicKey          *rsa.PublicKey
	accessTokenExpiry  time.Duration
	refreshTokenExpiry time.Duration
	issuer             string
}

// jwtCustomClaims extends jwt.RegisteredClaims with custom fields
type jwtCustomClaims struct {
	jwt.RegisteredClaims
	UserID    string           `json:"user_id"`
	Email     string           `json:"email"`
	TokenType entity.TokenType `json:"token_type"`
}

// NewRSAJWTService creates a new RSAJWTService by loading RSA keys from files
func NewRSAJWTService(cfg *config.JWTConfig) (*RSAJWTService, error) {
	// Load private key
	privateKeyBytes, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Load public key
	publicKeyBytes, err := os.ReadFile(cfg.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &RSAJWTService{
		privateKey:         privateKey,
		publicKey:          publicKey,
		accessTokenExpiry:  cfg.AccessTokenExpire,
		refreshTokenExpiry: cfg.RefreshTokenExpire,
		issuer:             cfg.Issuer,
	}, nil
}

// GenerateTokenPair generates access and refresh token pair
func (s *RSAJWTService) GenerateTokenPair(ctx context.Context, user *entity.User) (*entity.TokenPair, error) {
	now := time.Now().UTC()

	// Generate access token
	accessTokenJTI := uuid.New().String()
	accessTokenExp := now.Add(s.accessTokenExpiry)
	accessToken, err := s.generateToken(user, entity.TokenTypeAccess, accessTokenJTI, accessTokenExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshTokenJTI := uuid.New().String()
	refreshTokenExp := now.Add(s.refreshTokenExpiry)
	refreshToken, err := s.generateToken(user, entity.TokenTypeRefresh, refreshTokenJTI, refreshTokenExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return entity.NewTokenPair(accessToken, refreshToken, accessTokenExp, refreshTokenExp), nil
}

// generateToken creates a signed JWT token
func (s *RSAJWTService) generateToken(user *entity.User, tokenType entity.TokenType, jti string, expiresAt time.Time) (string, error) {
	now := time.Now().UTC()

	claims := jwtCustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   user.ID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
			ID:        jti,
		},
		UserID:    user.ID.String(),
		Email:     user.Email,
		TokenType: tokenType,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

// ValidateAccessToken validates and parses an access token
func (s *RSAJWTService) ValidateAccessToken(ctx context.Context, tokenString string) (*entity.JWTClaims, error) {
	return s.validateToken(tokenString, entity.TokenTypeAccess)
}

// ValidateRefreshToken validates and parses a refresh token
func (s *RSAJWTService) ValidateRefreshToken(ctx context.Context, tokenString string) (*entity.JWTClaims, error) {
	return s.validateToken(tokenString, entity.TokenTypeRefresh)
}

// validateToken validates and parses a token of specific type
func (s *RSAJWTService) validateToken(tokenString string, expectedType entity.TokenType) (*entity.JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwtCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*jwtCustomClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate token type
	if claims.TokenType != expectedType {
		return nil, fmt.Errorf("invalid token type: expected %s, got %s", expectedType, claims.TokenType)
	}

	// Validate issuer
	if claims.Issuer != s.issuer {
		return nil, fmt.Errorf("invalid token issuer")
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in token: %w", err)
	}

	return &entity.JWTClaims{
		UserID:    userID,
		Email:     claims.Email,
		TokenType: claims.TokenType,
		JTI:       claims.ID,
	}, nil
}

// ExtractJTI extracts JTI from token without full validation (for blacklist check)
func (s *RSAJWTService) ExtractJTI(tokenString string) (string, error) {
	// Parse without validation to extract JTI
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, &jwtCustomClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*jwtCustomClaims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}

	return claims.ID, nil
}
