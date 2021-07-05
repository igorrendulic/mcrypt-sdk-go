package crypto

import (
	"testing"

	"github.com/tj/assert"
)

func TestEncDecAes256(t *testing.T) {
	key, err := New32ByteKey()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("This should be encrypted")
	ciphertext, err := Aes256Encrypt(key, msg)

	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Aes256Decrypt(key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, plaintext, msg)
}

func TestEncodeDecodeAesKey(t *testing.T) {
	key, err := New32ByteKey()
	if err != nil {
		t.Fatal(err)
	}
	encode := ConfigEncodeAesKey(key)

	decoded, err := ConfigDecodeAesKey(encode)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, decoded, key)
}
