package mcrypt

import (
	crypt "github.com/igorrendulic/mcrypt-sdk-go/crypto"
)

type MCrypt struct {
	SignPrivKey crypt.PrivKey
	SignPubKey  crypt.PubKey
	EncPrivKey  crypt.PrivCKey
	EncPubKey   crypt.PubCKey
	keyConfig   *KeyConfig
}

// KeyConfig for JSON Configuration file (stored under home folder .dtable)
type KeyConfig struct {
	Pub       string `json:"pub"`
	Priv      string `json:"priv"`
	PubC      string `json:"pubC"`
	PrivC     string `json:"privC"`
	Domain    string `json:"domain"`
	SecretKey string `json:"secretKey"`
	filePath  string
}

type Key struct {
	id     []byte
	parent *Key
}

type KeyValue struct {
	Key   Key
	Value []byte
}
