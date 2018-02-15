package ring

import (
	"crypto/elliptic"
	crand "crypto/rand"
	"fmt"
	"io"

	"github.com/pkg/errors"
)

var (
	// ErrEmptyMessage is returned when trying to sign an empty message.
	ErrEmptyMessage = errors.New("you should provide a message to sign")

	// ErrInvalidSignerIndex is returned when an invalid signer index is provided to Sign.
	ErrInvalidSignerIndex = errors.New("the index of the signer should be in the ring")

	// ErrRingTooSmall is returned when the ring contains less than two participants.
	ErrRingTooSmall = errors.New("the ring is too small: you need at least two participants")
)

// Generate generates a new public-private key pair.
// If no random generator is provided, Generate will use
// go's default cryptographic random generator.
// The private key should be safely stored.
// The public key can be shared with anyone.
func Generate(rand io.Reader) (PublicKey, PrivateKey) {
	if rand == nil {
		rand = crand.Reader
	}

	curve := elliptic.P384()
	sk, x, y, err := elliptic.GenerateKey(curve, rand)
	if err != nil {
		panic(fmt.Sprintf("Could not generate keys: %s", err.Error()))
	}

	pk := elliptic.Marshal(curve, x, y)

	return PublicKey(pk), PrivateKey(sk)
}

// Signature is the struct representing a ring signature.
type Signature struct {
	ring []PublicKey
	e    []byte
	s    [][]byte
}

// Signing algorithm (Schnorr Ring Signature):
//	* Let (P(0),...,P(R-1)) be all the public keys in the ring
//	* P(i)=x(i)*G (x(i) is the private key)
//	* Let H be the chosen hash function (probably SHA256)
//	* Let N be the order of the curve.
//	* Let r be the index of the actual signer in the ring
//	* Randomly choose k in [1:N-1]
//	* Compute e(r+1 % R) = H(m || k*G)
//	* for i := r+1 % R; i != r; i++:
//		* Randomly choose s(i) in [1:N-1]
//		* Compute e(i+1 % R) = H(m || s(i)*G + e(i)*P(i))
//	* Compute s(r) = k - e(r)*x(r)
//	* Output signature: (P(0),...,P(1),e(0),s(0),...,s(r))

// Sign creates a ring signature for the given message.
func (sk PrivateKey) Sign(
	rand io.Reader,
	message []byte,
	ringKeys []PublicKey,
	signerIndex int,
) (*Signature, error) {
	if len(message) == 0 {
		return nil, ErrEmptyMessage
	}
	if signerIndex < 0 || len(ringKeys) <= signerIndex {
		return nil, ErrInvalidSignerIndex
	}
	if len(ringKeys) < 2 {
		return nil, ErrRingTooSmall
	}

	if rand == nil {
		rand = crand.Reader
	}

	return nil, nil
}

// randomParam generates a random scalar suitable
// for curve multiplication.
func randomParam(curve elliptic.Curve, rand io.Reader) ([]byte, error) {
	N := curve.Params().N
	bitSize := N.BitLen()
	byteLen := (bitSize + 7) >> 3
	k := make([]byte, byteLen)
	_, err := io.ReadFull(rand, k)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return k, nil
}

// Verifying algorithm:
//	* Let (P(0),...P(R-1),e,s(0),...,s(r)) be the input signature of message m
//	* Let ee = e
//	* for i := 0; i < R; i++:
//		* ee = H(m || s(i)*G + ee*P(i))
//	* If ee = e, signature is valid. Otherwise it's invalid.
