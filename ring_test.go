package ring_test

import (
	"crypto/elliptic"
	crand "crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	ring "github.com/t-bast/ring-signatures"
)

func TestElliptic(t *testing.T) {
	t.Run("Uses the same parameters across runs", func(t *testing.T) {
		c1 := elliptic.P384()
		c2 := elliptic.P384()

		assert.Equal(t, c1.Params().Gx, c2.Params().Gx, "Gx")
		assert.Equal(t, c1.Params().Gy, c2.Params().Gy, "Gy")
	})

	t.Run("Marshals and unmarshalls curve points", func(t *testing.T) {
		c := elliptic.P384()
		sk, x, y, err := elliptic.GenerateKey(c, crand.Reader)

		assert.NoError(t, err, "elliptic.GenerateKey()")
		assert.NotNil(t, sk, "Private Key")

		pk := elliptic.Marshal(c, x, y)
		x2, y2 := elliptic.Unmarshal(c, pk)

		assert.Equal(t, x, x2, "x")
		assert.Equal(t, y, y2, "y")
	})

	t.Run("Generates key pair", func(t *testing.T) {
		c := elliptic.P384()
		sk, x, y, err := elliptic.GenerateKey(c, crand.Reader)
		assert.NoError(t, err, "elliptic.GenerateKey()")

		px, py := c.ScalarBaseMult(sk)
		assert.Equal(t, x, px, "x")
		assert.Equal(t, y, py, "y")
	})

	t.Run("Curve order addition wraps around", func(t *testing.T) {
		c := elliptic.P384()
		k := new(big.Int).SetUint64(5)
		kn := new(big.Int).Add(k, c.Params().N)

		x1, y1 := c.ScalarBaseMult(k.Bytes())
		x2, y2 := c.ScalarBaseMult(kn.Bytes())

		assert.Equal(t, x1, x2, "x")
		assert.Equal(t, y1, y2, "y")
	})
}

func TestBigNumbers(t *testing.T) {
	t.Run("Positive big number is encoded in big-endian", func(t *testing.T) {
		encoded := new(big.Int).SetInt64(1<<3 + 1<<4 + 1<<5 + 1<<8 + 1<<10).Bytes()
		assert.Len(t, encoded, 2)
		assert.Equal(t, byte(0x05), encoded[0])
		assert.Equal(t, byte(0x38), encoded[1])
	})

	t.Run("Negative big number encodes the absolute value in big-endian", func(t *testing.T) {
		b := new(big.Int).SetInt64(-(1<<3 + 1<<4 + 1<<5 + 1<<8 + 1<<10))
		assert.Equal(t, -1, b.Sign())

		encoded := b.Bytes()
		assert.Len(t, encoded, 2)
		assert.Equal(t, byte(0x05), encoded[0])
		assert.Equal(t, byte(0x38), encoded[1])

		decoded := new(big.Int).SetBytes(encoded)
		assert.Equal(t, 1, decoded.Sign())
	})

	t.Run("Encode sign manually", func(t *testing.T) {
		b := new(big.Int).SetInt64(-(1<<3 + 1<<4 + 1<<5 + 1<<8 + 1<<10))
		assert.Equal(t, -1, b.Sign())

		encoded := b.Bytes()
		encoded[0] |= 1 << 7
		assert.Equal(t, byte(0x85), encoded[0])
	})

	t.Run("Multiple additions to bring back to positive values", func(t *testing.T) {
		n := new(big.Int).SetInt64(30)
		k := new(big.Int).SetInt64(25)
		e := new(big.Int).SetInt64(20)
		x := new(big.Int).SetInt64(21)

		s := k.Sub(k, e.Mul(e, x))
		assert.Equal(t, -1, s.Sign(), "Negative")
		assert.Equal(t, "-395", s.String())

		iter := 0
		for {
			if s.Sign() == 1 {
				break
			}

			s = s.Add(s, n)
			iter++
		}

		assert.Equal(t, "25", s.String())
		assert.Equal(t, 14, iter, "Number of iterations")
	})
}

func TestGenerate(t *testing.T) {
	pk, sk := ring.Generate(nil)

	t.Run("Correctly generates keys", func(t *testing.T) {
		assert.NotNil(t, pk, "Public Key")
		assert.NotNil(t, sk, "Private Key")
	})

	t.Run("Encodes and decodes public key", func(t *testing.T) {
		encoded := ring.ConfigEncodeKey(pk)
		assert.NotNil(t, encoded, "Encoded Public Key")

		decoded, err := ring.ConfigDecodeKey(encoded)
		assert.NoError(t, err, "ring.ConfigDecodeKey()")
		assert.EqualValues(t, pk, decoded, "Decoded Public Key")
	})

	t.Run("Encodes and decodes private key", func(t *testing.T) {
		encoded := ring.ConfigEncodeKey(sk)
		assert.NotNil(t, encoded, "Encoded Private Key")

		decoded, err := ring.ConfigDecodeKey(encoded)
		assert.NoError(t, err, "ring.ConfigDecodeKey()")
		assert.EqualValues(t, sk, decoded, "Decoded Private Key")
	})
}

func TestSign(t *testing.T) {
	alicePub, alicePriv := ring.Generate(nil)
	bobPub, bobPriv := ring.Generate(nil)
	carolPub, carolPriv := ring.Generate(nil)

	t.Run("Rejects empty messages", func(t *testing.T) {
		_, err := alicePriv.Sign(nil, nil, []ring.PublicKey{alicePub, bobPub, carolPub}, 0)
		assert.EqualError(t, err, ring.ErrEmptyMessage.Error())
	})

	t.Run("Rejects small ring", func(t *testing.T) {
		_, err := alicePriv.Sign(nil, []byte("hello"), []ring.PublicKey{alicePub}, 0)
		assert.EqualError(t, err, ring.ErrRingTooSmall.Error())
	})

	t.Run("Rejects invalid index", func(t *testing.T) {
		_, err := alicePriv.Sign(nil, []byte("hello"), []ring.PublicKey{alicePub, bobPub}, -1)
		assert.EqualError(t, err, ring.ErrInvalidSignerIndex.Error())

		_, err = alicePriv.Sign(nil, []byte("hello"), []ring.PublicKey{alicePub, bobPub}, 2)
		assert.EqualError(t, err, ring.ErrInvalidSignerIndex.Error())
	})

	t.Run("Sign without error", func(t *testing.T) {
		ringKeys := []ring.PublicKey{alicePub, bobPub, carolPub}
		signers := []ring.PrivateKey{alicePriv, bobPriv, carolPriv}

		message := []byte("Big Brother Is Watching")
		for i, signer := range signers {
			sig, err := signer.Sign(nil, message, ringKeys, i)
			assert.NoError(t, err, "signer.Sign()")
			assert.NotNil(t, sig, "Signature should not be empty")

			assert.True(t, sig.Verify(message), "Signature should be valid")
		}
	})
}
