package servercore

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

// tryDecryptPassword расшифровывает RSA-зашифрованный пароль из os-server-password.
func (s *Service) tryDecryptPassword(encryptedBase64, serverID string) string {
	if len(encryptedBase64) < 60 {
		return encryptedBase64
	}
	keyPath := s.cfg.ServerCore.SshPrivateKeyPath
	if keyPath == "" {
		return ""
	}
	pemData, err := os.ReadFile(keyPath)
	if err != nil {
		s.log.Warnf("servercore: RSA key read error for %s: %v", serverID, err)
		return ""
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return ""
	}
	var priv *rsa.PrivateKey
	// Поддержка PKCS1 и PKCS8.
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		priv = key
	} else if anyKey, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if k, ok := anyKey.(*rsa.PrivateKey); ok {
			priv = k
		}
	}
	if priv == nil {
		return ""
	}
	enc, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return ""
	}
	// OpenStack использует PKCS1 v1.5.
	if plain, err := rsa.DecryptPKCS1v15(nil, priv, enc); err == nil {
		return string(plain)
	}
	// Fallback: OAEP SHA-1.
	if plain, err := rsa.DecryptOAEP(sha1.New(), nil, priv, enc, nil); err == nil {
		return string(plain)
	}
	s.log.Warnf("servercore: RSA decrypt failed for %s", serverID)
	return ""
}

var _ = fmt.Sprintf
