package mcrypt

import (
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
