//go:build integration
// +build integration

// Package integration contains integration tests that require a running database.
package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dummy-event/internal/modules/auth/domain/entity"
	"github.com/dummy-event/internal/modules/auth/infrastructure/repository"
)

var testPool *pgxpool.Pool

// TestMain sets up the database connection for integration tests
func TestMain(m *testing.M) {
	ctx := context.Background()

	// Use test database URL or default
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://riandpratama@localhost:5432/dummy_event_test?sslmode=disable"
	}

	var err error
	testPool, err = pgxpool.New(ctx, dbURL)
	if err != nil {
		// Skip integration tests if database is not available
		os.Exit(0)
	}

	// Verify connection
	if err := testPool.Ping(ctx); err != nil {
		os.Exit(0)
	}

	// Run migrations for test database
	createTestTables(ctx, testPool)

	// Run tests
	code := m.Run()

	// Cleanup
	cleanupTestData(ctx, testPool)
	testPool.Close()

	os.Exit(code)
}

// createTestTables creates the necessary tables for testing
func createTestTables(ctx context.Context, pool *pgxpool.Pool) {
	query := `
		CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			email VARCHAR(255) UNIQUE NOT NULL,
			name VARCHAR(255) NOT NULL DEFAULT '',
			picture TEXT DEFAULT '',
			google_id VARCHAR(255) UNIQUE,
			password_hash VARCHAR(255),
			google_refresh_token_encrypted TEXT,
			email_verified BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			last_login_at TIMESTAMP WITH TIME ZONE
		);
	`
	pool.Exec(ctx, query)
}

// cleanupTestData removes all test data
func cleanupTestData(ctx context.Context, pool *pgxpool.Pool) {
	pool.Exec(ctx, "DELETE FROM users WHERE email LIKE '%@test.integration'")
}

func TestUserPostgresRepository_Integration(t *testing.T) {
	if testPool == nil {
		t.Skip("Database not available, skipping integration tests")
	}

	ctx := context.Background()
	repo := repository.NewUserPostgresRepository(testPool)

	// Use unique email for each test run
	testEmail := uuid.New().String() + "@test.integration"
	var testUserID uuid.UUID

	t.Run("Create user", func(t *testing.T) {
		user := entity.NewUser(testEmail, "Integration Test User")
		testUserID = user.ID

		err := repo.Create(ctx, user)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	})

	t.Run("Find user by ID", func(t *testing.T) {
		user, err := repo.FindByID(ctx, testUserID)
		if err != nil {
			t.Fatalf("FindByID() error = %v", err)
		}
		if user == nil {
			t.Fatal("FindByID() returned nil user")
		}
		if user.Email != testEmail {
			t.Errorf("FindByID() Email = %v, want %v", user.Email, testEmail)
		}
	})

	t.Run("Find user by email", func(t *testing.T) {
		user, err := repo.FindByEmail(ctx, testEmail)
		if err != nil {
			t.Fatalf("FindByEmail() error = %v", err)
		}
		if user == nil {
			t.Fatal("FindByEmail() returned nil user")
		}
		if user.ID != testUserID {
			t.Errorf("FindByEmail() ID = %v, want %v", user.ID, testUserID)
		}
	})

	t.Run("Update user", func(t *testing.T) {
		user, _ := repo.FindByID(ctx, testUserID)
		user.Name = "Updated Name"
		user.Picture = "https://new-picture.url"
		user.UpdatedAt = time.Now().UTC()

		err := repo.Update(ctx, user)
		if err != nil {
			t.Fatalf("Update() error = %v", err)
		}

		updated, _ := repo.FindByID(ctx, testUserID)
		if updated.Name != "Updated Name" {
			t.Errorf("Update() Name = %v, want Updated Name", updated.Name)
		}
	})

	t.Run("Update last login", func(t *testing.T) {
		err := repo.UpdateLastLogin(ctx, testUserID)
		if err != nil {
			t.Fatalf("UpdateLastLogin() error = %v", err)
		}

		user, _ := repo.FindByID(ctx, testUserID)
		if user.LastLoginAt == nil {
			t.Error("UpdateLastLogin() should set LastLoginAt")
		}
	})

	t.Run("Update Google refresh token", func(t *testing.T) {
		encryptedToken := "encrypted-refresh-token"
		err := repo.UpdateGoogleRefreshToken(ctx, testUserID, encryptedToken)
		if err != nil {
			t.Fatalf("UpdateGoogleRefreshToken() error = %v", err)
		}

		user, _ := repo.FindByID(ctx, testUserID)
		if user.GoogleRefreshTokenEncrypted == nil || *user.GoogleRefreshTokenEncrypted != encryptedToken {
			t.Error("UpdateGoogleRefreshToken() should set encrypted token")
		}
	})

	t.Run("Find by Google ID", func(t *testing.T) {
		// First, set a Google ID
		user, _ := repo.FindByID(ctx, testUserID)
		googleID := "google-" + uuid.New().String()
		user.GoogleID = &googleID
		repo.Update(ctx, user)

		found, err := repo.FindByGoogleID(ctx, googleID)
		if err != nil {
			t.Fatalf("FindByGoogleID() error = %v", err)
		}
		if found == nil {
			t.Fatal("FindByGoogleID() returned nil user")
		}
		if found.ID != testUserID {
			t.Errorf("FindByGoogleID() ID = %v, want %v", found.ID, testUserID)
		}
	})

	t.Run("Return nil for non-existent user", func(t *testing.T) {
		user, err := repo.FindByID(ctx, uuid.New())
		if err != nil {
			t.Fatalf("FindByID() error = %v", err)
		}
		if user != nil {
			t.Error("FindByID() should return nil for non-existent user")
		}

		user, err = repo.FindByEmail(ctx, "nonexistent@test.integration")
		if err != nil {
			t.Fatalf("FindByEmail() error = %v", err)
		}
		if user != nil {
			t.Error("FindByEmail() should return nil for non-existent user")
		}
	})

	// Cleanup this specific test user
	t.Cleanup(func() {
		testPool.Exec(ctx, "DELETE FROM users WHERE id = $1", testUserID)
	})
}

func TestDuplicateEmailConstraint_Integration(t *testing.T) {
	if testPool == nil {
		t.Skip("Database not available, skipping integration tests")
	}

	ctx := context.Background()
	repo := repository.NewUserPostgresRepository(testPool)

	testEmail := uuid.New().String() + "@test.integration"

	// Create first user
	user1 := entity.NewUser(testEmail, "User 1")
	err := repo.Create(ctx, user1)
	if err != nil {
		t.Fatalf("Create() first user error = %v", err)
	}

	// Try to create second user with same email
	user2 := entity.NewUser(testEmail, "User 2")
	err = repo.Create(ctx, user2)
	if err == nil {
		t.Error("Create() should fail for duplicate email")
	}

	// Cleanup
	t.Cleanup(func() {
		testPool.Exec(ctx, "DELETE FROM users WHERE email = $1", testEmail)
	})
}
