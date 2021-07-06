package mcrypt

import (
	"os"
	"testing"

	"github.com/igorrendulic/mcrypt-sdk-go/crypto"
	"github.com/tj/assert"
)

const (
	testPath = "/Users/igor/workspace/configfiles/dev.mailio.rendulic.me/igortest4-dtable-servicekeys.json"
)

func cleanupfiles(files ...string) {
	for _, file := range files {
		os.Remove(file)
	}
}

// test if signature keys derrived from private key match the loaded config
func TestEd25519PublicKeys(t *testing.T) {
	mcrypt := NewMCrypt(testPath)

	pubKey := mcrypt.SignPrivKey.GetPublic()
	signPubKey := mcrypt.SignPubKey

	assert.Equal(t, pubKey, signPubKey)
}

// test curve25519 encrypt/decrypt
func TestCurve25519(t *testing.T) {
	mcrypt := NewMCrypt(testPath)
	baseText := "this is test..."
	encrypted, err := mcrypt.EncPrivKey.Encrypt(mcrypt.EncPubKey, []byte(baseText))
	if err != nil {
		t.Fatal(err)
	}
	origText, err := mcrypt.EncPrivKey.Decrypt(mcrypt.EncPubKey, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, baseText, string(origText))
}

func TestCurve25519EncryptWithOtherServicesPublicKey(t *testing.T) {

	defer cleanupfiles("test-1.json", "test-2.json")

	_, err := GenerateRandomKeys("test.io", "test-1.json")
	if err != nil {
		t.Fatal(err)
	}
	_, err = GenerateRandomKeys("test2.io", "test-2.json")
	if err != nil {
		t.Fatal(err)
	}

	mcrypt1 := NewMCrypt("test-1.json")
	mcrypt2 := NewMCrypt("test-2.json")

	testMsg := "this is a test..."
	encTest, err := mcrypt1.EncPrivKey.Encrypt(mcrypt2.EncPubKey, []byte(testMsg))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := mcrypt2.EncPrivKey.Decrypt(mcrypt1.EncPubKey, encTest)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, testMsg, string(decrypted))
}

func TestCurve25519FailDecryptNotRightPublicKey(t *testing.T) {
	defer cleanupfiles("test-1.json", "test-2.json", "test-3.json")

	GenerateRandomKeys("test.io", "test-1.json")
	GenerateRandomKeys("test2.io", "test-2.json")
	GenerateRandomKeys("test3.io", "test-3.json")

	mcrypt1 := NewMCrypt("test-1.json")
	mcrypt2 := NewMCrypt("test-2.json")
	mcrypt3 := NewMCrypt("test-3.json")

	testMsg := "this is a test..."
	encTest, err := mcrypt1.EncPrivKey.Encrypt(mcrypt2.EncPubKey, []byte(testMsg))
	if err != nil {
		t.Fatal(err)
	}
	_, errDec := mcrypt3.EncPrivKey.Decrypt(mcrypt1.EncPubKey, encTest)
	assert.EqualError(t, errDec, crypto.ErrDecryptionFailed.Error())
}
