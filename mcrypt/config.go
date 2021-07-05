package mcrypt

import (
	"github.com/igorrendulic/mcrypt-sdk-go/crypto"
)

func NewKeyConfig(domain string) {
	SignPrivKey   crypto.PrivKey
	SignPubKey    crypto.PubKey
	EncPrivKey    crypto.PrivCKey
	EncPubKey     crypto.PubCKey
	KeyConfigFile *KeyConfig
}