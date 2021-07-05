package mcrypt

import (
	crypto_rand "crypto/rand"
	"fmt"
	"io"
	"regexp"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/igorrendulic/mcrypt-go-sdk/crypto"
)

const privateKeyLen = 24 + 24 + 32 + secretbox.Overhead

// Ed25519PrivateKey is an ed25519 private key
type Curve25519PrivateKey struct {
	Key *[32]byte
}

// Ed25519PublicKey is an ed25519 public key
type Curve25519PublicKey struct {
	Key *[32]byte
}

// Bytes marshals an ed25519 private key to protobuf bytes
func (k *Curve25519PrivateKey) Encrypt(recipientPublicKey crypto.PubCKey, payload []byte) ([]byte, error) {

	nonce, err := Nonce()
	if err != nil {
		return nil, err
	}
	cipher := box.Seal(nonce[:], payload, &nonce, recipientPublicKey.Raw(), k.Key)
	return cipher, nil
}

func (k *Curve25519PrivateKey) Decrypt(senderPublicKey crypto.PubCKey, encryptedPayload []byte) ([]byte, error) {
	var nonce [24]byte
	copy(nonce[:], encryptedPayload[:24])
	plain, ok := box.Open(nil, encryptedPayload[24:], &nonce, senderPublicKey.Raw(), k.Key)
	if !ok {
		return nil, fmt.Errorf("Fatal error decrypting")
	}
	return plain, nil
}

func (k *Curve25519PrivateKey) Raw() *[32]byte {
	return k.Key
}

func (k *Curve25519PublicKey) Raw() *[32]byte {
	return k.Key
}

func GenerateCryptKeys(src io.Reader) (crypto.PrivCKey, crypto.PubCKey, error) {
	pub, priv, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &Curve25519PrivateKey{Key: priv}, &Curve25519PublicKey{Key: pub}, nil
}

// HashBlake2x : https://blake2.net/blake2x.pdf
func HashBlake2x(key []byte) ([256]byte, error) {
	// key := []byte(str)
	var result [256]byte
	xof, err := blake2b.NewXOF(256, key)
	if err != nil {
		return result, err
	}

	if n, err := xof.Read(result[:]); err != nil {
		return result, err
	} else if n != len(result) {
		return result, err
	}
	return result, err
}

// ValidateAddress checks if address corresponds to farmiliar format
// The address is created as : encodeBase64(pubKey)->sha256->"0x" + substring(64-40,64);
func ValidateAddress(address string) bool {
	// /^0x[0-9a-fA-F]{40}$/.test(address)
	matched, err := regexp.MatchString("^0x[0-9a-fA-F]{40}$", address)
	if err != nil {
		return false
	}
	return matched
}

// Nonce of length 24 bytes
func Nonce() ([24]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(crypto_rand.Reader, nonce[:]); err != nil {
		return [24]byte{}, err
	}
	return nonce, nil
}

// New32ByteKey creates random 32-byte key for AES-256 GCM encryption
func New32ByteKey() ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(crypto_rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}
