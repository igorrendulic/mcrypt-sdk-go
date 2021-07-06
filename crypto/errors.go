package crypto

import "errors"

var (
	ErrDecryptionFailed = errors.New("message decryption failed")
	ErrEncryptFailed    = errors.New("message encryption failed")
)
