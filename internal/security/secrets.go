package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

type SecretBox struct {
	aead cipher.AEAD
}

func LoadSecretBox(path string) (*SecretBox, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read settings encryption key: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("decode settings encryption key: %w", err)
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("settings encryption key must be 32 bytes")
	}
	block, err := aes.NewCipher(decoded)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecretBox{aead: aead}, nil
}

func (s *SecretBox) Encrypt(value string) (string, error) {
	if s == nil || s.aead == nil {
		return "", fmt.Errorf("secret box is not initialized")
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := s.aead.Seal(nil, nonce, []byte(value), nil)
	out := append(nonce, sealed...)
	return base64.RawStdEncoding.EncodeToString(out), nil
}

func (s *SecretBox) Decrypt(value string) (string, error) {
	if s == nil || s.aead == nil {
		return "", fmt.Errorf("secret box is not initialized")
	}
	raw, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	if len(raw) < s.aead.NonceSize() {
		return "", fmt.Errorf("encrypted secret is malformed")
	}
	nonce, ciphertext := raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():]
	plain, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
