package tuf

import (
	"github.com/agl/ed25519"
	"github.com/flynn/tuf/data"
	"github.com/flynn/tuf/keys"
	"github.com/tent/canonical-json-go"
)

func Sign(s *data.Signed, k *keys.Key) {
	sig := ed25519.Sign(k.Private, s.Signed)
	s.Signatures = append(s.Signatures, data.Signature{
		KeyID:     k.ID,
		Method:    "ed25519",
		Signature: sig[:],
	})
}

func MarshalSigned(v interface{}, keys ...*keys.Key) (*data.Signed, error) {
	b, err := cjson.Marshal(v)
	if err != nil {
		return nil, err
	}
	s := &data.Signed{Signed: b}
	for _, k := range keys {
		Sign(s, k)
	}
	return s, nil
}
