// Package auth provides the auth module initialization and dependency injection.
package auth

import (
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/dummy-event/internal/config"
	"github.com/dummy-event/internal/modules/auth/application/usecase"
	"github.com/dummy-event/internal/modules/auth/infrastructure/email"
	"github.com/dummy-event/internal/modules/auth/infrastructure/encryption"
	"github.com/dummy-event/internal/modules/auth/infrastructure/jwt"
	"github.com/dummy-event/internal/modules/auth/infrastructure/oauth"
	"github.com/dummy-event/internal/modules/auth/infrastructure/otp"
	"github.com/dummy-event/internal/modules/auth/infrastructure/repository"
	httpHandler "github.com/dummy-event/internal/modules/auth/interfaces/http"
)

// Module represents the auth module with all its dependencies
type Module struct {
	Handler    *httpHandler.AuthHandler
	Middleware *httpHandler.AuthMiddleware
}

// NewModule creates a new auth module with all dependencies wired up
func NewModule(cfg *config.Config, dbPool *pgxpool.Pool, redisClient *redis.Client) (*Module, error) {
	// Initialize repositories
	userRepo := repository.NewUserPostgresRepository(dbPool)
	tokenRepo := repository.NewTokenRedisRepository(redisClient)
	otpRepo := repository.NewOTPRedisRepository(redisClient)

	// Initialize services
	jwtService, err := jwt.NewRSAJWTService(&cfg.JWT)
	if err != nil {
		return nil, err
	}

	oauthService := oauth.NewGoogleOAuthService(&cfg.Google)
	emailService := email.NewSMTPEmailService(&cfg.SMTP)
	otpService := otp.NewOTPGenerator(&cfg.OTP)

	encryptionService, err := encryption.NewAESEncryptionService()
	if err != nil {
		return nil, err
	}

	// Initialize use case
	authUseCase := usecase.NewAuthUseCase(
		cfg,
		userRepo,
		tokenRepo,
		otpRepo,
		jwtService,
		oauthService,
		emailService,
		otpService,
		encryptionService,
	)

	// Initialize HTTP handler and middleware
	handler := httpHandler.NewAuthHandler(authUseCase)
	middleware := httpHandler.NewAuthMiddleware(authUseCase)

	return &Module{
		Handler:    handler,
		Middleware: middleware,
	}, nil
}

// RegisterRoutes registers the auth module routes
func (m *Module) RegisterRoutes(app *fiber.App) {
	httpHandler.RegisterRoutes(app, m.Handler, m.Middleware)
}
