package mcrypt

import (
	"github.com/igorrendulic/mcrypt-sdk-go/crypto"
)

func NewMCrypt(pathToJSONKey string) *MCrypt {
	cfg, err := loadKeyConfigFromFile(pathToJSONKey)
	if err != nil {
		panic(err)
	}

	return &MCrypt{
		keyConfig: cfg,
	}
}

func (cfg *MCrypt) applyConfigKeys(config *KeyConfig) error {
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

	cfg.SignPrivKey = signPrivKey
	cfg.SignPubKey = signPubKey
	cfg.EncPrivKey = encKeyPriv
	cfg.EncPubKey = encKeyPub

	return nil
}
