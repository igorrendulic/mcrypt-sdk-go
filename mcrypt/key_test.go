package mcrypt

import "testing"

func TestKeyMarshalUnmarshal(t *testing.T) {
	key := NewKey([]byte("01234567890123456789012345678901a34567890123456789012345678901234567890123456789"))
	webKey := key.ToURLSafe()
	k, err := FromURLSafe(webKey)
	if err != nil {
		t.Fatal(err)
	}
	if !k.Equal(key) {
		t.Fatal("Keys not equal!")
	}
}

func TestKeyWithParent(t *testing.T) {
	key, err := NewKey([]byte("1234567890")).SetParent([]byte("imtheparent"))
	if err != nil {
		t.Fatal(err)
	}
	webKey := key.ToURLSafe()
	k, err := FromURLSafe(webKey)
	if err != nil {
		t.Fatal(err)
	}
	if !k.Equal(key) {
		t.Fatal("Keys not equal!")
	}

}
