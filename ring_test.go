package ring_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	ring "github.com/t-bast/ring-signatures"
)

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
