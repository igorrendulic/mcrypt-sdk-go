package crypto

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func TestED25519BasicSignAndVerify(t *testing.T) {
	priv, pub, err := GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("DTable crypto package")
	sig, err := priv.Sign(data)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := pub.Verify(data, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("signature didnt match")
	}
	// change data
	data[0] = ^data[0]
	ok, err = pub.Verify(data, sig)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("signature matched and shouldn't")
	}

}

func TestED25519Marshal(t *testing.T) {
	priv, pub, err := GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privBytes, err := priv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	privNew, err := UnmarshalEd25519PrivateKey(privBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Equals(privNew) || !privNew.Equals(priv) {
		t.Fatal("keys are not equal")
	}
	pubB, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pubNew, err := UnmarshalPublicKey(pubB)
	if err != nil {
		t.Fatal(err)
	}

	if !pub.Equals(pubNew) || !pubNew.Equals(pub) {
		t.Fatal("keys are not equal")
	}
}

func TestEncodeDecode(t *testing.T) {
	priv, _, err := GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privBytes, err := MarshalPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	encoded := ConfigEncodeKey(privBytes)
	fmt.Printf("Encoded: %s\n", encoded)

	keyBytes, err := ConfigDecodeKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := UnmarshalEd25519PrivateKey(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !privKey.Equals(priv) {
		t.Fatal("keys are not equal")
	}
}
