package ring

import (
	"encoding/base64"
)

// PublicKey defines a public key in assymetric encryption.
type PublicKey []byte

// PrivateKey defines a private key in assymetric encryption.
type PrivateKey []byte

// ConfigEncodeKey encodes a key to a friendly string format
// that can be stored in configuration files.
func ConfigEncodeKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// ConfigDecodeKey decodes a key from its friendly string format.
func ConfigDecodeKey(keyStr string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(keyStr)
}
