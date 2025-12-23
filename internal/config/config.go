// Package config provides centralized configuration management.
// It loads configuration from environment variables with validation.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all application configuration
type Config struct {
	App      AppConfig
	Database DatabaseConfig
	Redis    RedisConfig
	Google   GoogleOAuthConfig
	JWT      JWTConfig
	SMTP     SMTPConfig
	OTP      OTPConfig
}

// AppConfig holds application-level configuration
type AppConfig struct {
	Name string
	Env  string
	Port int
}

// DatabaseConfig holds PostgreSQL configuration
type DatabaseConfig struct {
	Host               string
	Port               int
	User               string
	Password           string
	Name               string
	SSLMode            string
	MaxConnections     int
	MaxIdleConnections int
	MaxLifetime        time.Duration
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

// GoogleOAuthConfig holds Google OAuth2 configuration
type GoogleOAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// JWTConfig holds JWT configuration with RSA keys
type JWTConfig struct {
	PrivateKeyPath     string
	PublicKeyPath      string
	AccessTokenExpire  time.Duration
	RefreshTokenExpire time.Duration
	Issuer             string
}

// SMTPConfig holds email SMTP configuration
type SMTPConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	From     string
	FromName string
}

// OTPConfig holds OTP configuration
type OTPConfig struct {
	Length        int
	ExpireMinutes time.Duration
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	// Load .env file if exists (ignore error if not found)
	_ = godotenv.Load()

	cfg := &Config{}

	// App configuration
	cfg.App = AppConfig{
		Name: getEnv("APP_NAME", "dummy-event"),
		Env:  getEnv("APP_ENV", "development"),
		Port: getEnvAsInt("APP_PORT", 3000),
	}

	// Database configuration
	cfg.Database = DatabaseConfig{
		Host:               getEnv("DB_HOST", "localhost"),
		Port:               getEnvAsInt("DB_PORT", 5432),
		User:               getEnv("DB_USER", "postgres"),
		Password:           getEnv("DB_PASSWORD", "postgres"),
		Name:               getEnv("DB_NAME", "dummy_event"),
		SSLMode:            getEnv("DB_SSL_MODE", "disable"),
		MaxConnections:     getEnvAsInt("DB_MAX_CONNECTIONS", 25),
		MaxIdleConnections: getEnvAsInt("DB_MAX_IDLE_CONNECTIONS", 5),
		MaxLifetime:        time.Duration(getEnvAsInt("DB_MAX_LIFETIME_MINUTES", 5)) * time.Minute,
	}

	// Redis configuration
	cfg.Redis = RedisConfig{
		Host:     getEnv("REDIS_HOST", "localhost"),
		Port:     getEnvAsInt("REDIS_PORT", 6379),
		Password: getEnv("REDIS_PASSWORD", ""),
		DB:       getEnvAsInt("REDIS_DB", 0),
	}

	// Google OAuth configuration
	cfg.Google = GoogleOAuthConfig{
		ClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
		ClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
		RedirectURL:  getEnv("GOOGLE_REDIRECT_URL", "http://localhost:3000/api/v1/auth/google/callback"),
	}

	// Validate required Google OAuth config
	if cfg.Google.ClientID == "" || cfg.Google.ClientSecret == "" {
		return nil, fmt.Errorf("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are required")
	}

	// JWT configuration
	cfg.JWT = JWTConfig{
		PrivateKeyPath:     getEnv("JWT_PRIVATE_KEY_PATH", "./keys/private.pem"),
		PublicKeyPath:      getEnv("JWT_PUBLIC_KEY_PATH", "./keys/public.pem"),
		AccessTokenExpire:  time.Duration(getEnvAsInt("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 15)) * time.Minute,
		RefreshTokenExpire: time.Duration(getEnvAsInt("JWT_REFRESH_TOKEN_EXPIRE_DAYS", 7)) * 24 * time.Hour,
		Issuer:             getEnv("JWT_ISSUER", "dummy-event"),
	}

	// SMTP configuration
	cfg.SMTP = SMTPConfig{
		Host:     getEnv("SMTP_HOST", "smtp.gmail.com"),
		Port:     getEnvAsInt("SMTP_PORT", 587),
		User:     getEnv("SMTP_USER", ""),
		Password: getEnv("SMTP_PASSWORD", ""),
		From:     getEnv("SMTP_FROM", ""),
		FromName: getEnv("SMTP_FROM_NAME", "Dummy Event"),
	}

	// OTP configuration
	cfg.OTP = OTPConfig{
		Length:        getEnvAsInt("OTP_LENGTH", 6),
		ExpireMinutes: time.Duration(getEnvAsInt("OTP_EXPIRE_MINUTES", 5)) * time.Minute,
	}

	return cfg, nil
}

// DSN returns the PostgreSQL connection string
func (d *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.Name, d.SSLMode,
	)
}

// RedisAddr returns the Redis address in host:port format
func (r *RedisConfig) RedisAddr() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

// IsDevelopment returns true if running in development mode
func (a *AppConfig) IsDevelopment() bool {
	return a.Env == "development"
}

// IsProduction returns true if running in production mode
func (a *AppConfig) IsProduction() bool {
	return a.Env == "production"
}

// getEnv gets environment variable with a default value
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// getEnvAsInt gets environment variable as integer with a default value
func getEnvAsInt(key string, defaultValue int) int {
	if valueStr, exists := os.LookupEnv(key); exists {
		if value, err := strconv.Atoi(valueStr); err == nil {
			return value
		}
	}
	return defaultValue
}
