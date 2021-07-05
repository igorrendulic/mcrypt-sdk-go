package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// Aes256Encrypt key must be 32 bytes long to have AES-256
func Aes256Encrypt(key []byte, plaintext []byte) ([]byte, error) {

	if len(key) != 32 {
		return nil, errors.New("Key must be 32 bytes long")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return aesgcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Aes256Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func ConfigEncodeAesKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

func ConfigDecodeAesKey(key string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(key)
}
