package crypto

import (
	"bytes"
	"fmt"
	"io"

	pb "github.com/igorrendulic/mcrypt-sdk-go/proto"
	"google.golang.org/protobuf/proto"

	"golang.org/x/crypto/ed25519"
)

// Ed25519PrivateKey is an ed25519 private key
type Ed25519PrivateKey struct {
	k ed25519.PrivateKey
}

// Ed25519PublicKey is an ed25519 public key
type Ed25519PublicKey struct {
	k ed25519.PublicKey
}

// GenerateEd25519Key generate a new ed25519 private and public key pair
func GenerateEd25519Key(src io.Reader) (PrivKey, PubKey, error) {
	pub, priv, err := ed25519.GenerateKey(src)
	if err != nil {
		return nil, nil, err
	}

	return &Ed25519PrivateKey{
			k: priv,
		},
		&Ed25519PublicKey{
			k: pub,
		},
		nil
}

func (k *Ed25519PrivateKey) Type() pb.KeyType {
	return pb.KeyType_Ed25519
}

// Bytes marshals an ed25519 private key to protobuf bytes
func (k *Ed25519PrivateKey) Bytes() ([]byte, error) {
	return MarshalPrivateKey(k)
}

func (k *Ed25519PrivateKey) Raw() ([]byte, error) {
	buf := make([]byte, len(k.k))
	copy(buf, k.k)
	return buf, nil
}

func (k *Ed25519PrivateKey) pubKeyBytes() []byte {
	return k.k[ed25519.PrivateKeySize-ed25519.PublicKeySize:]
}

// Equals compares two ed25519 private keys
func (k *Ed25519PrivateKey) Equals(o Key) bool {
	edk, ok := o.(*Ed25519PrivateKey)
	if !ok {
		return false
	}

	return bytes.Equal(k.k, edk.k)
}

// GetPublic returns an ed25519 public key from a private key
func (k *Ed25519PrivateKey) GetPublic() PubKey {
	return &Ed25519PublicKey{k: k.pubKeyBytes()}
}

// Sign returns a signature from an input message
func (k *Ed25519PrivateKey) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(k.k, msg), nil
}

func (k *Ed25519PublicKey) Type() pb.KeyType {
	return pb.KeyType_Ed25519
}

// Bytes returns a ed25519 public key as protobuf bytes
func (k *Ed25519PublicKey) Bytes() ([]byte, error) {
	return MarshalPublicKey(k)
}

func (k *Ed25519PublicKey) Raw() ([]byte, error) {
	return k.k, nil
}

// Equals compares two ed25519 public keys
func (k *Ed25519PublicKey) Equals(o Key) bool {
	edk, ok := o.(*Ed25519PublicKey)
	if !ok {
		return false
	}

	return bytes.Equal(k.k, edk.k)
}

// Verify checks a signature agains the input data
func (k *Ed25519PublicKey) Verify(data []byte, sig []byte) (bool, error) {
	return ed25519.Verify(k.k, data, sig), nil
}

func UnmarshalEd25519PublicKey(data []byte) (PubKey, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("expect ed25519 public key data size to be 32")
	}
	return &Ed25519PublicKey{
		k: ed25519.PublicKey(data),
	}, nil
}

func UnmarshalEd25519PrivateKey(keyBytes []byte) (PrivKey, error) {
	if len(keyBytes) == 0 {
		return nil, fmt.Errorf("private key required")
	}

	var privKey pb.PrivateKey
	err := proto.Unmarshal(keyBytes, &privKey)
	if err != nil {
		return nil, fmt.Errorf("Proto unmarshaling failed")
	}

	return &Ed25519PrivateKey{
		k: ed25519.PrivateKey(privKey.GetData()),
	}, nil
}
