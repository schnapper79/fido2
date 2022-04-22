package credentials

import (
	"bytes"

	"github.com/fxamacker/cbor/v2"
)

func Parser(raw []byte) (*AttestationObject, error) {
	var attest AttestationObjectRaw
	err := cbor.Unmarshal(raw, &attest)
	if err != nil {
		return nil, err
	}

	authData, err := parseAuthData(attest.AuthData)
	if err != nil {
		return nil, err
	}
	var attStmt AttStmtObject_ES256
	err = cbor.Unmarshal(attest.AttStmt, &attStmt)
	if err != nil {
		return nil, err
	}
	out := &AttestationObject{
		Fmt:      attest.Fmt,
		AttStmt:  &attStmt,
		AuthData: authData,
	}

	return out, nil

}

func parseAuthData(data []byte) (*AuthenticatorData, error) {
	var auth AuthenticatorData
	auth.RpIdHash = data[0:32]
	auth.Flags = data[32]
	auth.Counter = uint32(data[33])<<24 | uint32(data[34])<<16 | uint32(data[35])<<8 | uint32(data[36])
	rest := data[37:]
	if (auth.Flags & 0x40) == 0x40 {
		auth.AttCredData = &AttCredDataObject{
			Aaguid:    rest[0:16],
			CredIdLen: uint16(rest[16])<<8 | uint16(rest[17]),
		}
		auth.AttCredData.CredID = rest[18 : 18+auth.AttCredData.CredIdLen]
		restCborRaw := rest[18+auth.AttCredData.CredIdLen:]

		var key CoseKey
		dec := cbor.NewDecoder(bytes.NewReader(restCborRaw))
		err := dec.Decode(&key)
		if err != nil {
			return nil, err
		}
		auth.AttCredData.CredPubKey = &key
		if (auth.Flags & 0x80) == 0x80 {
			var ext ExtensionsList
			err = dec.Decode(&ext)
			if err != nil {
				return nil, err
			}
			auth.Extensions = &ext
		}
	} else if (auth.Flags & 0x80) == 0x80 {
		var ext ExtensionsList
		dec := cbor.NewDecoder(bytes.NewReader(rest))
		err := dec.Decode(&ext)
		if err != nil {
			return nil, err
		}
		auth.Extensions = &ext
	} else {
		_t := new(bool)
		_f := new(bool)

		*_t = true
		*_f = false
		auth.Extensions = &ExtensionsList{
			HmacSecret: _f,
		}
	}
	return &auth, nil
}
