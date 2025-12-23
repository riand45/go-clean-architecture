// Package oauth provides Google OAuth2 client implementation.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/dummy-event/internal/config"
	"github.com/dummy-event/internal/modules/auth/domain/entity"
	"github.com/dummy-event/internal/modules/auth/domain/service"
)

// Google OAuth2 endpoints
const (
	googleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
)

// Ensure implementation satisfies interface
var _ service.OAuthService = (*GoogleOAuthService)(nil)

// GoogleOAuthService implements OAuthService for Google
type GoogleOAuthService struct {
	config *oauth2.Config
}

// NewGoogleOAuthService creates a new GoogleOAuthService
func NewGoogleOAuthService(cfg *config.GoogleOAuthConfig) *GoogleOAuthService {
	oauthConfig := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	return &GoogleOAuthService{
		config: oauthConfig,
	}
}

// GetAuthURL generates the Google OAuth authorization URL
func (s *GoogleOAuthService) GetAuthURL(state string) string {
	// Request offline access to get refresh token
	return s.config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
}

// ExchangeCode exchanges authorization code for tokens
func (s *GoogleOAuthService) ExchangeCode(ctx context.Context, code string) (*entity.GoogleToken, error) {
	token, err := s.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	return &entity.GoogleToken{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		ExpiresAt:    token.Expiry,
	}, nil
}

// GetUserInfo retrieves user info from Google using access token
func (s *GoogleOAuthService) GetUserInfo(ctx context.Context, accessToken string) (*service.GoogleUserInfo, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleUserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authorization header
	req.Header.Set("Authorization", "Bearer "+accessToken)

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Google API error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var userInfo service.GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &userInfo, nil
}

// RefreshAccessToken refreshes Google access token using refresh token
func (s *GoogleOAuthService) RefreshAccessToken(ctx context.Context, refreshToken string) (*entity.GoogleToken, error) {
	// Create token source with refresh token
	tokenSource := s.config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken,
	})

	// Get new token
	token, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	return &entity.GoogleToken{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken, // May be empty if not rotated
		TokenType:    token.TokenType,
		ExpiresAt:    token.Expiry,
	}, nil
}
