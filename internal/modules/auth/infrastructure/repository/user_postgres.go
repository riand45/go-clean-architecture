// Package repository implements repository interfaces using PostgreSQL.
package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dummy-event/internal/modules/auth/domain/entity"
	"github.com/dummy-event/internal/modules/auth/domain/repository"
)

// Ensure implementation satisfies interface
var _ repository.UserRepository = (*UserPostgresRepository)(nil)

// UserPostgresRepository implements UserRepository using PostgreSQL
type UserPostgresRepository struct {
	pool *pgxpool.Pool
}

// NewUserPostgresRepository creates a new UserPostgresRepository
func NewUserPostgresRepository(pool *pgxpool.Pool) *UserPostgresRepository {
	return &UserPostgresRepository{pool: pool}
}

// FindByID retrieves a user by ID
func (r *UserPostgresRepository) FindByID(ctx context.Context, id uuid.UUID) (*entity.User, error) {
	query := `
		SELECT id, email, name, picture, google_id, password_hash, 
		       google_refresh_token_encrypted, email_verified, 
		       created_at, updated_at, last_login_at
		FROM users
		WHERE id = $1
	`

	user := &entity.User{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Name,
		&user.Picture,
		&user.GoogleID,
		&user.PasswordHash,
		&user.GoogleRefreshTokenEncrypted,
		&user.EmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // User not found
		}
		return nil, fmt.Errorf("failed to find user by ID: %w", err)
	}

	return user, nil
}

// FindByEmail retrieves a user by email address
func (r *UserPostgresRepository) FindByEmail(ctx context.Context, email string) (*entity.User, error) {
	query := `
		SELECT id, email, name, picture, google_id, password_hash, 
		       google_refresh_token_encrypted, email_verified, 
		       created_at, updated_at, last_login_at
		FROM users
		WHERE email = $1
	`

	user := &entity.User{}
	err := r.pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Name,
		&user.Picture,
		&user.GoogleID,
		&user.PasswordHash,
		&user.GoogleRefreshTokenEncrypted,
		&user.EmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // User not found
		}
		return nil, fmt.Errorf("failed to find user by email: %w", err)
	}

	return user, nil
}

// FindByGoogleID retrieves a user by Google ID
func (r *UserPostgresRepository) FindByGoogleID(ctx context.Context, googleID string) (*entity.User, error) {
	query := `
		SELECT id, email, name, picture, google_id, password_hash, 
		       google_refresh_token_encrypted, email_verified, 
		       created_at, updated_at, last_login_at
		FROM users
		WHERE google_id = $1
	`

	user := &entity.User{}
	err := r.pool.QueryRow(ctx, query, googleID).Scan(
		&user.ID,
		&user.Email,
		&user.Name,
		&user.Picture,
		&user.GoogleID,
		&user.PasswordHash,
		&user.GoogleRefreshTokenEncrypted,
		&user.EmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // User not found
		}
		return nil, fmt.Errorf("failed to find user by Google ID: %w", err)
	}

	return user, nil
}

// Create creates a new user
func (r *UserPostgresRepository) Create(ctx context.Context, user *entity.User) error {
	query := `
		INSERT INTO users (
			id, email, name, picture, google_id, password_hash,
			google_refresh_token_encrypted, email_verified,
			created_at, updated_at, last_login_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err := r.pool.Exec(ctx, query,
		user.ID,
		user.Email,
		user.Name,
		user.Picture,
		user.GoogleID,
		user.PasswordHash,
		user.GoogleRefreshTokenEncrypted,
		user.EmailVerified,
		user.CreatedAt,
		user.UpdatedAt,
		user.LastLoginAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// Update updates an existing user
func (r *UserPostgresRepository) Update(ctx context.Context, user *entity.User) error {
	query := `
		UPDATE users SET
			email = $2,
			name = $3,
			picture = $4,
			google_id = $5,
			password_hash = $6,
			google_refresh_token_encrypted = $7,
			email_verified = $8,
			updated_at = $9,
			last_login_at = $10
		WHERE id = $1
	`

	result, err := r.pool.Exec(ctx, query,
		user.ID,
		user.Email,
		user.Name,
		user.Picture,
		user.GoogleID,
		user.PasswordHash,
		user.GoogleRefreshTokenEncrypted,
		user.EmailVerified,
		user.UpdatedAt,
		user.LastLoginAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// UpdateGoogleRefreshToken updates the encrypted Google refresh token
func (r *UserPostgresRepository) UpdateGoogleRefreshToken(ctx context.Context, userID uuid.UUID, encryptedToken string) error {
	query := `
		UPDATE users SET
			google_refresh_token_encrypted = $2,
			updated_at = $3
		WHERE id = $1
	`

	result, err := r.pool.Exec(ctx, query, userID, encryptedToken, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("failed to update Google refresh token: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// UpdateLastLogin updates the last login timestamp
func (r *UserPostgresRepository) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE users SET
			last_login_at = $2,
			updated_at = $2
		WHERE id = $1
	`

	now := time.Now().UTC()
	result, err := r.pool.Exec(ctx, query, userID, now)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}
