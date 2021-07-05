package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"

	pb "github.com/igorrendulic/mcrypt-sdk-go/proto"
	"google.golang.org/protobuf/proto"
)

const (
	// Ed25519 is an enum for the supported Ed25519 key type
	Ed25519 = iota
)

var (
	// ErrBadKeyType is returned when a key is not supported
	ErrBadKeyType = errors.New("invalid or unsupported key type")
	// KeyTypes is a list of supported keys
	KeyTypes = []int{
		Ed25519,
	}
)

// PubKeyUnmarshaller is a func that creates a PubKey from a given slice of bytes
type PubKeyUnmarshaller func(data []byte) (PubKey, error)

// PrivKeyUnmarshaller is a func that creates a PrivKey from a given slice of bytes
type PrivKeyUnmarshaller func(data []byte) (PrivKey, error)

// PubKeyUnmarshallers is a map of unmarshallers by key type
var PubKeyUnmarshallers = map[pb.KeyType]PubKeyUnmarshaller{
	pb.KeyType_Ed25519: UnmarshalEd25519PublicKey,
}

// PrivKeyUnmarshallers is a map of unmarshallers by key type
var PrivKeyUnmarshallers = map[pb.KeyType]PrivKeyUnmarshaller{
	pb.KeyType_Ed25519: UnmarshalEd25519PrivateKey,
}

// Key represents a crypto key that can be compared to another key
type Key interface {
	// Bytes returns a serialized, storeable representation of this key
	// DEPRECATED in favor of Marshal / Unmarshal
	Bytes() ([]byte, error)

	// Equals checks whether two PubKeys are the same
	Equals(Key) bool

	// Raw returns the raw bytes of the key (not wrapped in the
	// libp2p-crypto protobuf).
	//
	// This function is the inverse of {Priv,Pub}KeyUnmarshaler.
	Raw() ([]byte, error)

	// Type returns the protobof key type.
	Type() pb.KeyType
}

// PrivKey represents a private key that can be used to generate a public key,
// sign data, and decrypt data that was encrypted with a public key
type PrivKey interface {
	Key

	// Cryptographically sign the given bytes
	Sign([]byte) ([]byte, error)

	// Return a public key paired with this private key
	GetPublic() PubKey
}

type PrivCKey interface {
	Raw() *[32]byte
	Encrypt(PubCKey, []byte) ([]byte, error)
	Decrypt(PubCKey, []byte) ([]byte, error)
}

type PubCKey interface {
	Raw() *[32]byte
}

// PubKey is a public key
type PubKey interface {
	Key

	// Verify that 'sig' is the signed hash of 'data'
	Verify(data []byte, sig []byte) (bool, error)
}

// GenSharedKey generates the shared key from a given private key
type GenSharedKey func([]byte) ([]byte, error)

// GenerateKeyPairWithReader returns a keypair of the given type and bitsize
func GenerateKeyPairWithReader(typ int32, src io.Reader) (PrivKey, PubKey, error) {
	switch typ {
	case Ed25519:
		return GenerateEd25519Key(src)
	default:
		return nil, nil, ErrBadKeyType
	}
}

// UnmarshalPrivateKey converts a protobuf serialized private key into its
// representative object
func UnmarshalPrivateKey(data []byte) (PrivKey, error) {
	pmes := new(pb.PrivateKey)
	err := proto.Unmarshal(data, pmes)
	if err != nil {
		return nil, err
	}

	um, ok := PrivKeyUnmarshallers[pmes.GetType()]
	if !ok {
		return nil, ErrBadKeyType
	}

	return um(pmes.GetData())
}

// MarshalPrivateKey converts a key object into its protobuf serialized form.
func MarshalPrivateKey(k PrivKey) ([]byte, error) {
	pbmes := new(pb.PrivateKey)
	pbmes.Type = k.Type()
	data, err := k.Raw()
	if err != nil {
		return nil, err
	}

	pbmes.Data = data
	return proto.Marshal(pbmes)
}

// UnmarshalPublicKey converts a protobuf serialized public key into its
// representative object
func UnmarshalPublicKey(data []byte) (PubKey, error) {
	pmes := new(pb.PublicKey)
	err := proto.Unmarshal(data, pmes)
	if err != nil {
		return nil, err
	}

	um, ok := PubKeyUnmarshallers[pmes.GetType()]
	if !ok {
		return nil, ErrBadKeyType
	}

	return um(pmes.GetData())
}

// MarshalPublicKey converts a public key object into a protobuf serialized
// public key
func MarshalPublicKey(k PubKey) ([]byte, error) {
	pbmes := new(pb.PublicKey)
	pbmes.Type = k.Type()
	data, err := k.Raw()
	if err != nil {
		return nil, err
	}
	pbmes.Data = data

	return proto.Marshal(pbmes)
}

// ConfigDecodeKey decodes from b64 (for config file), and unmarshals.
func ConfigDecodeKey(b string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(b)
}

func ConfigEncodeEncryptKey(key *[32]byte) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

func ConfigDecodeEncryptKey(b string) (*[32]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(b)
	if err != nil {
		return nil, err
	}
	var key [32]byte
	copy(key[:], decoded[:32])
	return &key, nil
}

// func ConfigDecodeCPrivateKey(b string) (*[32]byte, error) {
// 	decoded, err := base64.StdEncoding.DecodeString(b)
// 	if err != nil {
// 		return nil, err
// 	}
// 	var key [32]byte
// 	copy(key[:], decoded[:32])
// 	return &key, nil
// }

// ConfigEncodeKey encodes to b64 (for config file), and marshals.
func ConfigEncodeKey(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// KeyEqual checks whether two
func KeyEqual(k1, k2 Key) bool {
	if k1 == k2 {
		return true
	}

	b1, err1 := k1.Bytes()
	b2, err2 := k2.Bytes()
	return bytes.Equal(b1, b2) && err1 == err2
}
