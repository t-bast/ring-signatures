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

// Signing algorithm (Schnorr Ring Signature):
//	* Let (P(0),...,P(R-1)) be all the public keys in the ring
//	* P(i)=x(i)*G (x(i) is the private key)
//	* Let H be the chosen hash function (probably SHA256)
//	* Let n be the number of bits of the private key
//	* Let r be the index of the actual signer in the ring
//	* Randomly choose k in {0,1}^n
//	* Compute e(r+1 % R) = H(m || k*G)
//	* for i := r+1 % R; i != r; i++:
//		* Randomly choose s(i) in {0,1}^n
//		* Compute e(i+1 % R) = H(m || s(i)*G + e(i)*P(i))
//	* Compute s(r) = k - e(r)*x(r)
//	* Output signature: (P(0),...,P(1),e(0),s(0),...,s(r))

// Verifying algorithm:
//	* Let (P(0),...P(R-1),e,s(0),...,s(r)) be the input signature of message m
//	* Let ee = e
//	* for i := 0; i < R; i++:
//		* ee = H(m || s(i)*G + ee*P(i))
//	* If ee = e, signature is valid. Otherwise it's invalid.
