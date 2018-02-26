package ring

import (
	"crypto/elliptic"
	crand "crypto/rand"
	"math/big"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
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
	pk, sk := Generate(nil)

	t.Run("Correctly generates keys", func(t *testing.T) {
		assert.NotNil(t, pk, "Public Key")
		assert.NotNil(t, sk, "Private Key")
	})

	t.Run("Encodes and decodes public key", func(t *testing.T) {
		encoded := ConfigEncodeKey(pk)
		assert.NotNil(t, encoded, "Encoded Public Key")

		decoded, err := ConfigDecodeKey(encoded)
		assert.NoError(t, err, "ConfigDecodeKey()")
		assert.EqualValues(t, pk, decoded, "Decoded Public Key")
	})

	t.Run("Encodes and decodes private key", func(t *testing.T) {
		encoded := ConfigEncodeKey(sk)
		assert.NotNil(t, encoded, "Encoded Private Key")

		decoded, err := ConfigDecodeKey(encoded)
		assert.NoError(t, err, "ConfigDecodeKey()")
		assert.EqualValues(t, sk, decoded, "Decoded Private Key")
	})
}

func TestSign(t *testing.T) {
	alicePub, alicePriv := Generate(nil)
	bobPub, bobPriv := Generate(nil)
	carolPub, carolPriv := Generate(nil)

	t.Run("Rejects empty messages", func(t *testing.T) {
		_, err := alicePriv.Sign(nil, nil, []PublicKey{alicePub, bobPub, carolPub}, 0)
		assert.EqualError(t, err, ErrEmptyMessage.Error())
	})

	t.Run("Rejects small ring", func(t *testing.T) {
		_, err := alicePriv.Sign(nil, []byte("hello"), []PublicKey{alicePub}, 0)
		assert.EqualError(t, err, ErrRingTooSmall.Error())
	})

	t.Run("Rejects invalid index", func(t *testing.T) {
		_, err := alicePriv.Sign(nil, []byte("hello"), []PublicKey{alicePub, bobPub}, -1)
		assert.EqualError(t, err, ErrInvalidSignerIndex.Error())

		_, err = alicePriv.Sign(nil, []byte("hello"), []PublicKey{alicePub, bobPub}, 2)
		assert.EqualError(t, err, ErrInvalidSignerIndex.Error())
	})

	t.Run("Sign without error", func(t *testing.T) {
		ringKeys := []PublicKey{alicePub, bobPub, carolPub}
		signers := []PrivateKey{alicePriv, bobPriv, carolPriv}

		message := []byte("Big Brother Is Watching")
		for i, signer := range signers {
			sig, err := signer.Sign(nil, message, ringKeys, i)
			assert.NoError(t, err, "signer.Sign()")
			assert.NotNil(t, sig, "Signature should not be empty")

			assert.True(t, sig.Verify(message), "Signature should be valid")
		}
	})
}

func TestVerify(t *testing.T) {
	alicePub, alicePriv := Generate(nil)
	bobPub, _ := Generate(nil)

	t.Run("Empty signature", func(t *testing.T) {
		sig := &Signature{}
		assert.False(t, sig.Verify([]byte("hello")))
	})

	t.Run("Small ring", func(t *testing.T) {
		sig := &Signature{ring: []PublicKey{alicePub}}
		assert.False(t, sig.Verify([]byte("you again?")))
	})

	t.Run("Missing e", func(t *testing.T) {
		sig := &Signature{
			ring: []PublicKey{alicePub, bobPub},
			s:    make([][]byte, 2),
		}
		assert.False(t, sig.Verify([]byte("you again?")))
	})

	t.Run("Invalid format", func(t *testing.T) {
		sig := &Signature{
			ring: []PublicKey{alicePub, bobPub},
			e:    []byte("who's watching?"),
			s:    make([][]byte, 3),
		}
		assert.False(t, sig.Verify([]byte("you again?")))
	})

	t.Run("Message does not match", func(t *testing.T) {
		message := []byte("very secret much hidden")
		sig, err := alicePriv.Sign(nil, message, []PublicKey{alicePub, bobPub}, 0)

		assert.NoError(t, err)
		assert.True(t, sig.Verify(message))
		assert.False(t, sig.Verify([]byte("not hidden very insecure")))
	})

	t.Run("Invalid signer index", func(t *testing.T) {
		message := []byte("very secret much hidden")
		sig, err := alicePriv.Sign(nil, message, []PublicKey{alicePub, bobPub}, 1)

		assert.NoError(t, err)
		assert.False(t, sig.Verify(message))
	})
}

// GenerateKeys generates a set of keys for benchmarks.
func GenerateKeys(count int) ([]PublicKey, []PrivateKey) {
	pubKeys := make([]PublicKey, count)
	privKeys := make([]PrivateKey, count)
	for i := 0; i < count; i++ {
		pub, priv := Generate(nil)
		pubKeys[i] = pub
		privKeys[i] = priv
	}
	return pubKeys, privKeys
}

func benchmarkSign(ringSize int, b *testing.B) {
	pubKeys, privKeys := GenerateKeys(ringSize)
	i := rand.Intn(ringSize)
	message := []byte("Benchmark me like the french people do.")
	for n := 0; n < b.N; n++ {
		_, err := privKeys[i].Sign(nil, message, pubKeys, i)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign3(b *testing.B)   { benchmarkSign(3, b) }
func BenchmarkSign10(b *testing.B)  { benchmarkSign(10, b) }
func BenchmarkSign100(b *testing.B) { benchmarkSign(100, b) }

func benchmarkVerify(ringSize int, b *testing.B) {
	pubKeys, privKeys := GenerateKeys(ringSize)
	i := rand.Intn(ringSize)
	message := []byte("Benchmark me like the french people do.")
	sig, err := privKeys[i].Sign(nil, message, pubKeys, i)
	if err != nil {
		b.Fatal(err)
	}

	for n := 0; n < b.N; n++ {
		valid := sig.Verify(message)
		if !valid {
			b.Fatalf("Signature verification failed.")
		}
	}
}

func BenchmarkVerify3(b *testing.B)   { benchmarkVerify(3, b) }
func BenchmarkVerify10(b *testing.B)  { benchmarkVerify(10, b) }
func BenchmarkVerify100(b *testing.B) { benchmarkVerify(100, b) }
