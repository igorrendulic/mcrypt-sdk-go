package mcrypt

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/igorrendulic/mcrypt-sdk-go/crypto"
	"github.com/igorrendulic/mcrypt-sdk-go/utils"
)

func newKeyConfig(domain string, outputfile string) (*KeyConfig, error) {
	cfg := KeyConfig{}
	c, err := cfg.createConfig(domain, outputfile)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// LoadKeyConfigFile from filepath
func loadKeyConfigFromFile(filePath string) (*KeyConfig, error) {
	exists, err := utils.Exists(filePath)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("Config file not found")
	}
	dat, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var conf *KeyConfig
	err = json.Unmarshal(dat, &conf)
	if err != nil {
		return nil, err
	}
	conf.filePath = filePath

	return conf, nil
}

func (config *KeyConfig) createConfig(domain, outputfilePath string) (*KeyConfig, error) {
	// check if keys for domain already exist in the local folder
	exists, err := utils.Exists(outputfilePath)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.New("File already exists! If you override it you might loose the keys")
	}

	priv, pub, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate keys: %v\n", err)
		return nil, err
	}
	privBytes, err := priv.Bytes()
	if err != nil {
		fmt.Printf("failed to encode private key: %v\n", err)
		return nil, err
	}
	pubBytes, err := pub.Bytes()
	if err != nil {
		fmt.Printf("failed to encode public key: %v\n", err)
		return nil, err
	}

	privCKey, pubCKey, err := crypto.GenerateCryptKeys(rand.Reader)
	if err != nil {
		return nil, err
	}
	encodedPrivateCryptoKey := crypto.ConfigEncodeEncryptKey(privCKey.Raw())
	encodedPublicCryptoKey := crypto.ConfigEncodeEncryptKey(pubCKey.Raw())

	encodedPrivate := crypto.ConfigEncodeKey(privBytes)
	encodedPublic := crypto.ConfigEncodeKey(pubBytes)

	conf := &KeyConfig{
		Domain: domain,
		Priv:   encodedPrivate,
		Pub:    encodedPublic,
		PrivC:  encodedPrivateCryptoKey,
		PubC:   encodedPublicCryptoKey,
	}

	err = conf.save(outputfilePath)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Key succesfully generated for domain: %s, path: %s\n Please make sure to backup this file. You'll be needing it for user registration in your service!\n", domain, outputfilePath)

	return conf, nil
}

func (conf *KeyConfig) save(filePath string) error {

	configJSON, err := json.Marshal(conf)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filePath, configJSON, 0644)
	if err != nil {
		return err
	}
	return nil
}

func (config *KeyConfig) validateKeyConf() error {
	if config.Domain == "" {
		return errors.New("Domain is missing in config file")
	}
	if config.Priv == "" {
		return errors.New("Private key is missing in config file")
	}
	if config.Pub == "" {
		return errors.New("Public key is missing in config file")
	}
	if config.PrivC == "" {
		return errors.New("Private encryption key is missing in config file")
	}
	if config.PubC == "" {
		return errors.New("Public encryption key is missing in config file")
	}
	return nil
}
