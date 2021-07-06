# mcrypt-sdk-go

Encryption and ID generation library for Mail.io. 

## Usage: 

Encrypt and decrypt with single key pair
```go
    mcrypt := NewMCrypt(testPath)
	baseText := "this is test..."
	encrypted, err := mcrypt.EncPrivKey.Encrypt(mcrypt.EncPubKey, []byte(baseText))
	if err != nil {
		t.Fatal(err)
	}
	origText, err := mcrypt.EncPrivKey.Decrypt(mcrypt.EncPubKey, encrypted)
	if err != nil {
		t.Fatal(err)
	}
```

Encrypt/Descrypt for recipient with specific public key (PK exchange required prior)

```go
	mcrypt1 := NewMCrypt("test-1.json")
	mcrypt2 := NewMCrypt("test-2.json")

	testMsg := "this is a test..."
	encTest, err := mcrypt1.EncPrivKey.Encrypt(mcrypt2.EncPubKey, []byte(testMsg))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := mcrypt2.EncPrivKey.Decrypt(mcrypt1.EncPubKey, encTest)
	if err != nil {
		t.Fatal(err)
	}
```

