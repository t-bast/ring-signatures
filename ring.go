package ring

import (
	"fmt"
	"io"

	"golang.org/x/crypto/ed25519"
)

// Generate generates a new public-private key pair.
// The private key should be safely stored.
// The public key can be shared with anyone.
func Generate(rand io.Reader) (PublicKey, PrivateKey) {
	pk, sk, err := ed25519.GenerateKey(rand)
	if err != nil {
		panic(fmt.Sprintf("Could not generate keys: %s", err.Error()))
	}

	return PublicKey(pk), PrivateKey(sk)
}
