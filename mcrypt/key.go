package mcrypt

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"

	pb "github.com/igorrendulic/mcrypt-sdk-go/proto"
	"github.com/igorrendulic/mcrypt-sdk-go/utils"
	"google.golang.org/protobuf/proto"
)

type keyEnc struct {
	ID     []byte
	Parent []byte
}

// NewKey creates a key with user specificed ID
func NewKey(id interface{}) *Key {

	str, _ := utils.ToString(id)
	return &Key{
		id: []byte(str),
	}
}

// NewKeyAutoID creates a table reference with auto generated ID
func NewKeyAutoID() *Key {
	return &Key{}
}

// SetParent sets the parent key of the key
func (k *Key) SetParent(parent interface{}) (*Key, error) {
	if k.id == nil {
		return k, errors.New("setting parent requires key value")
	}
	str, err := utils.ToString(parent)
	if err != nil {
		return k, err
	}
	k.parent = &Key{
		id: []byte(str),
	}
	return k, nil
}

// // NewKeyWithParent creates a key with ancestor (parent)
// func NewKeyWithParent(parent, key interface{}) Key {
// 	strParent, _ := toString(parent)
// 	str, _ := toString(key)

// 	parentBytes := []byte(strParent)
// 	keyBytes := []byte(str)
// 	combinedKey := append(parentBytes, keyBytes...)
// 	return Key{
// 		id: combinedKey,
// 	}
// }

func (k *Key) valid() bool {
	if k == nil {
		return false
	}
	// // possible parents
	// for ; k != nil; k = k.Parent {
	// 	if k.Parent != nil {

	// 	}
	// }
	return true
}

// Equal compares keys and determines if the key contents are all equal
func (k *Key) Equal(o *Key) bool {

	for {
		if k == nil || o == nil {
			return k == o // if either is nil, both must be nil
		}
		if !bytes.Equal(k.id, o.id) {
			return false
		}
		if k.parent == nil && o.parent == nil {
			return true
		}
		k = k.parent
		o = o.parent
	}
	return false
}

// Get returns string value of key
func (k *Key) Get() string {
	if k == nil {
		return ""
	}
	return string(k.id)
}

// Bytes returns key in bytes including the parentId (key must have id before it has Parent)
func (k *Key) Bytes() []byte {
	if k == nil {
		return nil
	}
	if k.id == nil && k.parent == nil {
		return nil
	}
	if k.id == nil {
		return nil
	}
	if k.parent == nil {
		return k.id
	}
	return append(k.parent.id, k.id...)
}

func marshalKey(k *Key) (string, error) {
	t := &pb.Key{
		Id: k.Bytes(),
	}
	r, err := proto.Marshal(t)
	if err != nil {
		return "", err
	}
	// Trailing padding is stripped.
	b64 := strings.TrimRight(base64.URLEncoding.EncodeToString(r), "=")
	return b64, nil
}

func unmarshalKey(encoded string) (*Key, error) {
	// Re-add padding.
	if m := len(encoded) % 4; m != 0 {
		encoded += strings.Repeat("=", 4-m)
	}
	b, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	pKey := new(pb.Key)
	if err := proto.Unmarshal(b, pKey); err != nil {
		return nil, err
	}
	key := &Key{
		id: pKey.GetId(),
	}
	return key, nil
}

// ToURLSafe - converting key to be representable for web
func (k *Key) ToURLSafe() string {
	encodedKey, _ := marshalKey(k)
	return encodedKey
}

// FromURLSafe - converting web key representation for key back to native key
func FromURLSafe(encodedKey string) (*Key, error) {
	return unmarshalKey(encodedKey)
}
