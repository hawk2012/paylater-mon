// Package users — система пользователей с ролями и хранением в Vault (пункт 20 IMPROVEMENTS.md).
// Роли: superadmin (главный админ, может всё), admin (может менять настройки), user (только просмотр/операции).
// Хранилище: Vault kv/paylater-mon/users (JSON).
// Если хранилища нет — создаётся автоматически с пользователем admin/admin (superadmin, mustChangePassword=true).
package users

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Role — роль пользователя.
type Role string

const (
	RoleSuperAdmin Role = "superadmin"
	RoleAdmin      Role = "admin"
	RoleUser       Role = "user"
)

// User — модель пользователя.
type User struct {
	Username           string    `json:"username"`
	PasswordHash       string    `json:"password_hash"`
	Role               Role      `json:"role"`
	MustChangePassword bool      `json:"must_change_password"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	Disabled           bool      `json:"disabled"`
}

// VaultBackend — интерфейс для взаимодействия с Vault (минимальный).
type VaultBackend interface {
	ReadUsers(ctx context.Context) ([]byte, error)
	WriteUsers(ctx context.Context, data []byte) error
}

// Store — хранилище пользователей.
type Store struct {
	mu      sync.Mutex
	backend VaultBackend
	users   map[string]*User
	loaded  bool
}

// New создаёт хранилище пользователей.
func New(backend VaultBackend) *Store {
	return &Store{backend: backend, users: map[string]*User{}}
}

// Load загружает пользователей из Vault. Если хранилище пусто — создаёт admin/admin.
func (s *Store) Load(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.backend.ReadUsers(ctx)
	if err == nil && len(data) > 0 {
		var list []User
		if json.Unmarshal(data, &list) == nil {
			s.users = map[string]*User{}
			for i := range list {
				s.users[list[i].Username] = &list[i]
			}
			s.loaded = true
			return nil
		}
	}

	// Хранилище пусто или ошибка — создаём дефолтного admin/admin.
	hash := hashPassword("admin")
	admin := &User{
		Username:           "admin",
		PasswordHash:       hash,
		Role:               RoleSuperAdmin,
		MustChangePassword: true,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	s.users = map[string]*User{"admin": admin}
	s.loaded = true

	// Пытаемся сохранить в Vault.
	saved, _ := json.Marshal([]User{*admin})
	_ = s.backend.WriteUsers(ctx, saved)
	return nil
}

// Authenticate проверяет credentials и возвращает пользователя.
func (s *Store) Authenticate(username, password string) (*User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok || u.Disabled {
		return nil, false
	}
	if u.PasswordHash != hashPassword(password) {
		return nil, false
	}
	return u, true
}

// Get возвращает пользователя по имени.
func (s *Store) Get(username string) (*User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return nil, false
	}
	return u, true
}

// List возвращает всех пользователей.
func (s *Store) List() []User {
	s.mu.Lock()
	defer s.mu.Unlock()
	var list []User
	for _, u := range s.users {
		list = append(list, *u)
	}
	return list
}

// Create создаёт нового пользователя.
func (s *Store) Create(ctx context.Context, username, password string, role Role, mustChange bool) error {
	s.mu.Lock()
	if _, exists := s.users[username]; exists {
		s.mu.Unlock()
		return fmt.Errorf("user %s already exists", username)
	}
	if !isValidRole(role) {
		s.mu.Unlock()
		return fmt.Errorf("invalid role: %s", role)
	}
	now := time.Now()
	s.users[username] = &User{
		Username:           username,
		PasswordHash:       hashPassword(password),
		Role:               role,
		MustChangePassword: mustChange,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	users := s.snapshot()
	s.mu.Unlock()
	return s.persist(ctx, users)
}

// UpdatePassword меняет пароль пользователя.
func (s *Store) UpdatePassword(ctx context.Context, username, oldPassword, newPassword string) error {
	s.mu.Lock()
	u, ok := s.users[username]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("user not found")
	}
	if oldPassword != "" && u.PasswordHash != hashPassword(oldPassword) {
		s.mu.Unlock()
		return fmt.Errorf("wrong current password")
	}
	u.PasswordHash = hashPassword(newPassword)
	u.MustChangePassword = false
	u.UpdatedAt = time.Now()
	users := s.snapshot()
	s.mu.Unlock()
	return s.persist(ctx, users)
}

// AdminResetPassword — сброс пароля администратором (без старого пароля).
func (s *Store) AdminResetPassword(ctx context.Context, caller Role, username, newPassword string, mustChange bool) error {
	if caller != RoleSuperAdmin && caller != RoleAdmin {
		return fmt.Errorf("insufficient privileges")
	}
	s.mu.Lock()
	u, ok := s.users[username]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("user not found")
	}
	u.PasswordHash = hashPassword(newPassword)
	u.MustChangePassword = mustChange
	u.UpdatedAt = time.Now()
	users := s.snapshot()
	s.mu.Unlock()
	return s.persist(ctx, users)
}

// UpdateRole меняет роль пользователя. Superadmin нельзя понизить.
func (s *Store) UpdateRole(ctx context.Context, caller Role, username string, newRole Role) error {
	if caller != RoleSuperAdmin {
		return fmt.Errorf("only superadmin can change roles")
	}
	if !isValidRole(newRole) {
		return fmt.Errorf("invalid role")
	}
	s.mu.Lock()
	u, ok := s.users[username]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("user not found")
	}
	if u.Role == RoleSuperAdmin && newRole != RoleSuperAdmin {
		// Проверяем, что это не последний superadmin.
		superCount := 0
		for _, u2 := range s.users {
			if u2.Role == RoleSuperAdmin {
				superCount++
			}
		}
		if superCount <= 1 {
			s.mu.Unlock()
			return fmt.Errorf("cannot demote the last superadmin")
		}
	}
	u.Role = newRole
	u.UpdatedAt = time.Now()
	users := s.snapshot()
	s.mu.Unlock()
	return s.persist(ctx, users)
}

// Delete удаляет пользователя. Superadmin нельзя удалить (если он последний).
func (s *Store) Delete(ctx context.Context, caller Role, username string) error {
	if caller != RoleSuperAdmin && caller != RoleAdmin {
		return fmt.Errorf("insufficient privileges")
	}
	s.mu.Lock()
	u, ok := s.users[username]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("user not found")
	}
	if u.Role == RoleSuperAdmin {
		superCount := 0
		for _, u2 := range s.users {
			if u2.Role == RoleSuperAdmin {
				superCount++
			}
		}
		if superCount <= 1 {
			s.mu.Unlock()
			return fmt.Errorf("cannot delete the last superadmin")
		}
	}
	delete(s.users, username)
	users := s.snapshot()
	s.mu.Unlock()
	return s.persist(ctx, users)
}

// CanEditConfig — может ли роль редактировать конфигурацию.
func CanEditConfig(role Role) bool {
	return role == RoleSuperAdmin || role == RoleAdmin
}

// CanManageUsers — может ли роль управлять пользователями.
func CanManageUsers(role Role) bool {
	return role == RoleSuperAdmin
}

// CanPerformOperations — может ли роль выполнять операции (restart, delete и т.д.).
func CanPerformOperations(role Role) bool {
	return true // все роли могут
}

func (s *Store) snapshot() []User {
	var list []User
	for _, u := range s.users {
		list = append(list, *u)
	}
	return list
}

func (s *Store) persist(ctx context.Context, users []User) error {
	data, err := json.Marshal(users)
	if err != nil {
		return err
	}
	return s.backend.WriteUsers(ctx, data)
}

func isValidRole(r Role) bool {
	return r == RoleSuperAdmin || r == RoleAdmin || r == RoleUser
}

func hashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

// GenerateRandomPassword генерирует случайный пароль заданной длины.
func GenerateRandomPassword(length int) string {
	if length < 8 {
		length = 12
	}
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%"
	b := make([]byte, length)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}
