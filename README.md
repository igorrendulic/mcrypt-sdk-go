# mcrypt-sdk-go

Encryption and ID generation library for Mail.io. 

## Usage: 

Create new keys (curve25519 and ed25519 for signing)
```go
GenerateRandomKeys("mydomain.com", "keys.json")
```

Encrypt and decrypt with single key pair
```go
    mcrypt := NewMCrypt(testPath)
	baseText := "this is test..."
	encrypted, err := mcrypt.EncPrivKey.Encrypt(mcrypt.EncPubKey, []byte(baseText))
	
	origText, err := mcrypt.EncPrivKey.Decrypt(mcrypt.EncPubKey, encrypted)
	
```

Encrypt/Descrypt for recipient with specific public key (PK exchange required prior)

```go
	mcrypt1 := NewMCrypt("test-1.json")
	mcrypt2 := NewMCrypt("test-2.json")

	testMsg := "this is a test..."
	encTest, err := mcrypt1.EncPrivKey.Encrypt(mcrypt2.EncPubKey, []byte(testMsg))

	decrypted, err := mcrypt2.EncPrivKey.Decrypt(mcrypt1.EncPubKey, encTest)
```

ed25519 Sign and Verify signature

```go
	mcrypt := NewMCrypt("test-sign-1.json")
	signature, err := mcrypt.SignPrivKey.Sign([]byte(msgToSign))
	
	isValid, err := mcrypt.SignPubKey.Verify([]byte(msgToSign), signature)
```

AES256 (Keys must be 32 bytes)

```go
    
    key, err := crypto.New32ByteKey()
	msg := "this is plain message"
	encrypted, err := crypto.Aes256Encrypt(key, []byte(msg))
	decrypted, err := crypto.Aes256Decrypt(key, encrypted)
```

Generate URL safe Keys for database (byte keys)

```go
key := NewKey([]byte("01234567890123456789012345678901a34567890123456789012345678901234567890123456789"))
	webKey := key.ToURLSafe()
	k, err := FromURLSafe(webKey)
```

Validate Mailio Handshake (ed25519)

```go
	mcrypt := NewMCrypt("test-domain.json")

	isValid, err := mcrypt.VerifyMailioHandshake(base64PublicKey, base64Signature, plainTextContract)
```