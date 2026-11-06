// Package secrets — резолвер секретных ссылок из Vault (пункт 22 IMPROVEMENTS.md).
// Если config.SecretRefs.Enabled=true, значения полей вида "vault:key_name"
// заменяются на реальные значения из Vault (kv/data/paylater-mon/config/key_name).
package secrets

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"paylater-mon/internal/config"
)

// VaultReader — интерфейс для чтения секретов из Vault.
type VaultReader interface {
	ReadSecretRef(ctx context.Context, path string) (string, error)
	WriteSecretRef(ctx context.Context, path, value string) error
}

// Resolver — резолвер секретных ссылок.
type Resolver struct {
	cfg    *config.Config
	vault  VaultReader
	prefix string
}

// New создаёт резолвер.
func New(cfg *config.Config, vault VaultReader) *Resolver {
	prefix := cfg.SecretRefs.VaultPrefix
	if prefix == "" {
		prefix = "kv/data/paylater-mon/config"
	}
	return &Resolver{cfg: cfg, vault: vault, prefix: prefix}
}

// ApplyConfig обновляет конфигурацию на лету (без перезапуска).
func (r *Resolver) ApplyConfig(cfg *config.Config) {
	r.cfg = cfg
	r.prefix = cfg.SecretRefs.VaultPrefix
	if r.prefix == "" {
		r.prefix = "kv/data/paylater-mon/config"
	}
}

// Enabled — включён ли режим шифрования секретов.
func (r *Resolver) Enabled() bool {
	return r.cfg.SecretRefs.Enabled && r.vault != nil
}

// ResolveAll обходит все строковые поля Config и заменяет "vault:key" на значения из Vault.
func (r *Resolver) ResolveAll(ctx context.Context) error {
	if !r.Enabled() {
		return nil
	}
	return r.resolveStruct(ctx, reflect.ValueOf(r.cfg).Elem())
}

func (r *Resolver) resolveStruct(ctx context.Context, v reflect.Value) error {
	if v.Kind() != reflect.Struct {
		return nil
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := v.Field(i)
		if !field.CanInterface() {
			continue
		}
		switch field.Kind() {
		case reflect.String:
			val := field.String()
			if strings.HasPrefix(val, "vault:") {
				key := strings.TrimPrefix(val, "vault:")
				path := r.prefix + "/" + key
				resolved, err := r.vault.ReadSecretRef(ctx, path)
				if err != nil {
					return fmt.Errorf("secrets: resolve %s: %w", key, err)
				}
				field.SetString(resolved)
			}
		case reflect.Struct:
			if err := r.resolveStruct(ctx, field); err != nil {
				return err
			}
		}
	}
	return nil
}

// MigrateToVault записывает все секретные поля конфига в Vault и заменяет значения на "vault:key".
// Секретные поля определяются по имени (содержит password, token, key, secret).
func (r *Resolver) MigrateToVault(ctx context.Context) error {
	if r.vault == nil {
		return fmt.Errorf("vault not available")
	}
	return r.migrateStruct(ctx, reflect.ValueOf(r.cfg).Elem(), "")
}

func (r *Resolver) migrateStruct(ctx context.Context, v reflect.Value, prefix string) error {
	if v.Kind() != reflect.Struct {
		return nil
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := v.Field(i)
		if !field.CanInterface() || !field.CanSet() {
			continue
		}
		yamlTag := t.Field(i).Tag.Get("yaml")
		name := strings.Split(yamlTag, ",")[0]
		if name == "" {
			name = strings.ToLower(t.Field(i).Name)
		}
		key := name
		if prefix != "" {
			key = prefix + "_" + name
		}
		switch field.Kind() {
		case reflect.String:
			val := field.String()
			if val == "" || strings.HasPrefix(val, "vault:") {
				continue
			}
			lowerKey := strings.ToLower(key)
			if isSecretField(lowerKey) {
				path := r.prefix + "/" + key
				if err := r.vault.WriteSecretRef(ctx, path, val); err != nil {
					return fmt.Errorf("secrets: migrate %s: %w", key, err)
				}
				field.SetString("vault:" + key)
			}
		case reflect.Struct:
			if err := r.migrateStruct(ctx, field, key); err != nil {
				return err
			}
		}
	}
	return nil
}

func isSecretField(name string) bool {
	return strings.Contains(name, "password") ||
		strings.Contains(name, "token") ||
		strings.Contains(name, "secret") ||
		strings.Contains(name, "api_key") ||
		strings.Contains(name, "webhook_url")
}
