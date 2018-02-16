package ring

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMarshal(t *testing.T) {
	alicePub, alicePriv := Generate(nil)
	bobPub, _ := Generate(nil)

	sig, err := alicePriv.Sign(nil, []byte("yo"), []PublicKey{alicePub, bobPub}, 0)
	assert.NoError(t, err, "Sign()")

	b, err := sig.Marshal()
	assert.NoError(t, err, "Marshal()")

	unmarshalled := &Signature{}
	err = unmarshalled.Unmarshal(b)
	assert.NoError(t, err, "Unmarshal()")
	assert.EqualValues(t, sig, unmarshalled)

	assert.True(t, unmarshalled.Verify([]byte("yo")))
}

func TestEncode(t *testing.T) {
	alicePub, alicePriv := Generate(nil)
	bobPub, _ := Generate(nil)

	sig, err := alicePriv.Sign(nil, []byte("42"), []PublicKey{alicePub, bobPub}, 0)
	assert.NoError(t, err, "Sign()")

	s, err := sig.Encode()
	assert.NoError(t, err, "Encode()")

	decoded := &Signature{}
	err = decoded.Decode(s)
	assert.NoError(t, err, "Decode()")
	assert.EqualValues(t, sig, decoded)

	assert.True(t, decoded.Verify([]byte("42")))
}
