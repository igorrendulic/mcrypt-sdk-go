package mcrypt

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"

	"github.com/igorrendulic/mcrypt-sdk-go/crypto"
)

/**
* Main class implementing ed25519 cruve25519 and aes256/aes512 encrrytion algorithms
**/
func NewMCrypt(pathToJSONKey string) *MCrypt {
	cfg, err := loadKeyConfigFromFile(pathToJSONKey)
	if err != nil {
		panic(err)
	}

	m := &MCrypt{
		keyConfig: cfg,
	}

	err = m.applyConfigKeys(cfg)
	if err != nil {
		panic(err)
	}

	return m
}

/**
* Generates a new file with random encryption keys
**/
func GenerateRandomKeys(domain string, outputfilepath string) (*MCrypt, error) {
	_, err := newKeyConfig(domain, outputfilepath)
	if err != nil {
		return nil, err
	}

	return NewMCrypt(outputfilepath), err
}

func (m *MCrypt) applyConfigKeys(config *KeyConfig) error {
	//(crypto.PrivKey, crypto.PubKey, *crypto.Curve25519PrivateKey, *crypto.Curve25519PublicKey, error)
	err := config.validateKeyConf()
	if err != nil {
		return err
	}

	privSignKey, err := crypto.ConfigDecodeKey(config.Priv)
	pubSignKey, err := crypto.ConfigDecodeKey(config.Pub)
	privEncKey, err := crypto.ConfigDecodeEncryptKey(config.PrivC)
	pubEncKey, err := crypto.ConfigDecodeEncryptKey(config.PubC)

	signPrivKey, err := crypto.UnmarshalEd25519PrivateKey(privSignKey)
	signPubKey, err := crypto.UnmarshalPublicKey(pubSignKey)
	if err != nil {
		return err
	}
	encKeyPriv := &crypto.Curve25519PrivateKey{Key: privEncKey}
	encKeyPub := &crypto.Curve25519PublicKey{Key: pubEncKey}

	m.SignPrivKey = signPrivKey
	m.SignPubKey = signPubKey
	m.EncPrivKey = encKeyPriv
	m.EncPubKey = encKeyPub

	return nil
}

/**
* ! this method should not be used server side. It's mainly to validate VerifyHandshake and for completeness sake
* The handshakes are always created client side (check mobile SDK or Javascript SDK)
* Creates base64 encoded signature of the contract content
**/
func (mc *MCrypt) CreateHandshake(handshakePrivateKey, handshakeContract string) (*string, error) {
	privSignKey, err := crypto.ConfigDecodeKey(handshakePrivateKey)
	if err != nil {
		return nil, err
	}
	signPrivKey, err := crypto.UnmarshalEd25519PrivateKey(privSignKey)
	if err != nil {
		return nil, err
	}

	signature, err := signPrivKey.Sign([]byte(handshakeContract))
	if err != nil {
		return nil, err
	}

	sign := base64.StdEncoding.EncodeToString(signature)
	return &sign, nil
}

/**
* Handshake signature validation
* Handshake is a signed contract by the users private key
* Contract can be:
* - stringified json file
* - user address (e.g. mailio address)
* - Id reference to a unique public/private contract
**/
func (mc *MCrypt) VerifyMailioHandshake(handshakeOwnersPublicKey, handshakeSignature, handshakeContract string) (bool, error) {

	pubKey, err := crypto.ConfigDecodeKey(handshakeOwnersPublicKey)
	if err != nil {
		return false, err
	}

	if len(pubKey) != ed25519.PublicKeySize {
		return false, errors.New("invalid size of public key")
	}

	sign, err := base64.StdEncoding.DecodeString(handshakeSignature)
	if err != nil {
		return false, err
	}

	if len(sign) != ed25519.SignatureSize {
		return false, errors.New("invalid signature size")
	}

	signPubKey, err := crypto.UnmarshalEd25519PublicKey(pubKey)
	if err != nil {
		return false, err
	}

	return signPubKey.Verify([]byte(handshakeContract), sign)
}
