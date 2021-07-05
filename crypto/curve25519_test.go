package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/tj/assert"
)

func TestEncryptDecrypt(t *testing.T) {
	prKey, pbKey, err := GenerateCryptKeys(rand.Reader)

	encSenderPrivateKey := ConfigEncodeEncryptKey(prKey.Raw())
	privKey, err := ConfigDecodeEncryptKey(encSenderPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	senderPrivateKey := &Curve25519PrivateKey{Key: privKey}

	encSenderPublicKey := ConfigEncodeEncryptKey(pbKey.Raw())
	pubKey, err := ConfigDecodeEncryptKey(encSenderPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	senderPublicKey := &Curve25519PublicKey{Key: pubKey}

	if err != nil {
		t.Fatal(err)
	}
	recipientPrivateKey, recipientPublicKey, err := GenerateCryptKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("Alas, poor Yorick! I knew him, Horatio")
	encrypted, err := senderPrivateKey.Encrypt(recipientPublicKey, msg)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := recipientPrivateKey.Decrypt(senderPublicKey, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, decrypted, msg)
}
