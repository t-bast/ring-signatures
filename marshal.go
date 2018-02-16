package ring

import (
	"encoding/base64"
	"encoding/json"
)

// Marshal marshals a signature to a byte representation.
func (sig *Signature) Marshal() ([]byte, error) {
	return json.Marshal(struct {
		R []PublicKey
		S [][]byte
		E []byte
	}{
		R: sig.ring,
		S: sig.s,
		E: sig.e,
	})
}

// Unmarshal unmarshals a signature from its byte representation.
func (sig *Signature) Unmarshal(data []byte) error {
	unmarshalled := struct {
		R []PublicKey
		S [][]byte
		E []byte
	}{}
	err := json.Unmarshal(data, &unmarshalled)
	if err != nil {
		return err
	}

	sig.ring = unmarshalled.R
	sig.e = unmarshalled.E
	sig.s = unmarshalled.S

	return nil
}

// Encode encodes a signature to a friendly string representation.
func (sig *Signature) Encode() (string, error) {
	b, err := sig.Marshal()
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

// Decode decodes a signature from its friendly string representation.
func (sig *Signature) Decode(data string) error {
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return err
	}

	err = sig.Unmarshal(b)
	if err != nil {
		return err
	}

	return nil
}
