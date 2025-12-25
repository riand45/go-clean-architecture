// Package mocks provides mock implementations for testing.
package mocks

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/dummy-event/internal/modules/auth/domain/entity"
)

// MockUserRepository is a mock implementation of UserRepository
type MockUserRepository struct {
	Users         map[uuid.UUID]*entity.User
	UsersByEmail  map[string]*entity.User
	UsersByGoogle map[string]*entity.User
	CreateErr     error
	UpdateErr     error
	FindErr       error
}

// NewMockUserRepository creates a new MockUserRepository
func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		Users:         make(map[uuid.UUID]*entity.User),
		UsersByEmail:  make(map[string]*entity.User),
		UsersByGoogle: make(map[string]*entity.User),
	}
}

func (m *MockUserRepository) FindByID(ctx context.Context, id uuid.UUID) (*entity.User, error) {
	if m.FindErr != nil {
		return nil, m.FindErr
	}
	return m.Users[id], nil
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*entity.User, error) {
	if m.FindErr != nil {
		return nil, m.FindErr
	}
	return m.UsersByEmail[email], nil
}

func (m *MockUserRepository) FindByGoogleID(ctx context.Context, googleID string) (*entity.User, error) {
	if m.FindErr != nil {
		return nil, m.FindErr
	}
	return m.UsersByGoogle[googleID], nil
}

func (m *MockUserRepository) Create(ctx context.Context, user *entity.User) error {
	if m.CreateErr != nil {
		return m.CreateErr
	}
	m.Users[user.ID] = user
	m.UsersByEmail[user.Email] = user
	if user.GoogleID != nil {
		m.UsersByGoogle[*user.GoogleID] = user
	}
	return nil
}

func (m *MockUserRepository) Update(ctx context.Context, user *entity.User) error {
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	m.Users[user.ID] = user
	m.UsersByEmail[user.Email] = user
	if user.GoogleID != nil {
		m.UsersByGoogle[*user.GoogleID] = user
	}
	return nil
}

func (m *MockUserRepository) UpdateGoogleRefreshToken(ctx context.Context, userID uuid.UUID, encryptedToken string) error {
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	if user, ok := m.Users[userID]; ok {
		user.GoogleRefreshTokenEncrypted = &encryptedToken
	}
	return nil
}

func (m *MockUserRepository) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	if user, ok := m.Users[userID]; ok {
		now := time.Now().UTC()
		user.LastLoginAt = &now
	}
	return nil
}

// AddUser adds a user to the mock repository
func (m *MockUserRepository) AddUser(user *entity.User) {
	m.Users[user.ID] = user
	m.UsersByEmail[user.Email] = user
	if user.GoogleID != nil {
		m.UsersByGoogle[*user.GoogleID] = user
	}
}
