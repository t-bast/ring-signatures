package ring

import (
	"bytes"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

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
//	* for i := r+1 % R; i != r; i++%R:
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

	es := make([][]byte, len(ringKeys))
	ss := make([][]byte, len(ringKeys))

	curve := elliptic.P384()
	r := len(ringKeys)

	// Initialize the ring.

	k, err := randomParam(curve, rand)
	if err != nil {
		return nil, err
	}

	x, y := curve.ScalarBaseMult(k)
	es[(signerIndex+1)%r] = hash(append(message, elliptic.Marshal(curve, x, y)...))

	// Iterate over the whole ring.

	for i := (signerIndex + 1) % r; i != signerIndex; i = (i + 1) % r {
		s, err := randomParam(curve, rand)
		if err != nil {
			return nil, err
		}

		ss[i] = s

		x1, y1 := curve.ScalarBaseMult(ss[i])
		px, py := elliptic.Unmarshal(curve, ringKeys[i])
		x2, y2 := curve.ScalarMult(px, py, es[i])
		x, y = curve.Add(x1, y1, x2, y2)
		es[(i+1)%r] = hash(append(message, elliptic.Marshal(curve, x, y)...))
	}

	// Close the ring.

	valK := new(big.Int).SetBytes(k)
	valE := new(big.Int).SetBytes(es[signerIndex])
	valX := new(big.Int).SetBytes(sk)
	valS := new(big.Int).Sub(valK, new(big.Int).Mul(valE, valX))

	// It's highly likely that s will end up negative.
	// This is bad because go big numbers drop the sign and encode the absolute
	// value when getting the bytes.
	// We leverage the fact that since N is the order of the curve, (x+N)*P=x*P
	// to get a positive value that will have the same impact on elliptic curve
	// operations.
	if valS.Sign() == -1 {
		add := new(big.Int).Mul(valE, curve.Params().N)
		valS = valS.Add(valS, add)

		if valS.Sign() == 0 {
			// Tough luck...
			return nil, errors.New("could not produce ring signature")
		}
	}

	ss[signerIndex] = valS.Bytes()

	sig := &Signature{
		ring: ringKeys,
		e:    es[0],
		s:    ss,
	}

	return sig, nil
}

// randomParam generates a random scalar suitable
// for curve multiplication.
func randomParam(curve elliptic.Curve, rand io.Reader) ([]byte, error) {
	for {
		r, err := crand.Int(rand, curve.Params().N)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		if r.Sign() == 1 {
			return r.Bytes(), nil
		}
	}
}

// hash hashes the given bytes.
func hash(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// Verifying algorithm:
//	* Let (P(0),...P(R-1),e,s(0),...,s(r)) be the input signature of message m
//	* Let ee = e
//	* for i := 0; i < R; i++:
//		* ee = H(m || s(i)*G + ee*P(i))
//	* If ee = e, signature is valid. Otherwise it's invalid.

// Verify verifies the validity of the message signature.
// It does not detail why the signature validation failed.
func (sig *Signature) Verify(message []byte) bool {
	if sig == nil {
		return false
	}

	if len(sig.ring) < 2 {
		return false
	}

	if len(sig.s) != len(sig.ring) {
		return false
	}

	if len(sig.e) == 0 {
		return false
	}

	curve := elliptic.P384()

	e := make([]byte, len(sig.e))
	copy(e, sig.e)

	for i := 0; i < len(sig.ring); i++ {
		x1, y1 := curve.ScalarBaseMult(sig.s[i])
		px, py := elliptic.Unmarshal(curve, sig.ring[i])
		x2, y2 := curve.ScalarMult(px, py, e)

		x, y := curve.Add(x1, y1, x2, y2)
		e = hash(append(message, elliptic.Marshal(curve, x, y)...))
	}

	return bytes.Equal(e, sig.e)
}
