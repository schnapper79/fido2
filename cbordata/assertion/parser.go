package assertion

import (
	"bytes"
	"fido2/mycrypto"

	"github.com/fxamacker/cbor/v2"
)

func Parser(raw []byte, sharedSecret []byte) (*AssertionReplyObjectParsed, error) {
	var assert AssertionReplyObjectRaw
	err := cbor.Unmarshal(raw, &assert)
	if err != nil {
		return nil, err
	}

	authData, err := parseAuthData(assert.AuthData)
	if err != nil {
		return nil, err
	}

	out := &AssertionReplyObjectParsed{
		Credential:          assert.Credential,
		AuthData:            authData,
		Signature:           assert.Signature,
		User:                assert.User,
		NumberOfCredentials: assert.NumberOfCredentials,
	}

	if (out.AuthData.Extensions != nil) && (out.AuthData.Extensions.HmacSecret != nil) && (len(out.AuthData.Extensions.HmacSecret)) > 0 {
		//have one salt:
		out.AuthData.Extensions.Secret, err = mycrypto.Aes256_Dec(out.AuthData.Extensions.HmacSecret, sharedSecret)
		if err != nil {
			return nil, err
		}
	}
	return out, nil

}

func parseAuthData(data []byte) (*AuthData, error) {
	var auth AuthData
	auth.RpIdHash = data[0:32]
	auth.Flags = data[32]
	auth.Counter = uint32(data[33])<<24 | uint32(data[34])<<16 | uint32(data[35])<<8 | uint32(data[36])
	rest := data[37:]

	if (auth.Flags & 0x80) == 0x80 {
		var ext ExtensionsListReply
		dec := cbor.NewDecoder(bytes.NewReader(rest))
		err := dec.Decode(&ext)
		if err != nil {
			return nil, err
		}
		auth.Extensions = &ext
	} else {
		auth.Extensions = &ExtensionsListReply{
			HmacSecret: []byte{},
		}
	}

	return &auth, nil
}
