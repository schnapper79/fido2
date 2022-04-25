package fido2

import (
	"bytes"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const CMD_authenticatorMakeCredential = 0x01

type PublicKeyCredentialRpEntity struct {
	Name string `cbor:"name"`
	Id   string `cbor:"id"`
}
type PublicKeyCredentialUserEntity struct {
	Id          []byte `cbor:"id"`
	Name        string `cbor:"name,omitempty"`
	DisplayName string `cbor:"displayName,omitempty"`
}
type PubKeyCredParamsItem struct {
	Alg  int    `cbor:"alg"`
	Type string `cbor:"type"`
}
type ExcludeCredential struct {
	ID   []byte `cbor:"id"`
	Type string `cbor:"type"`
}
type Options struct {
	Rk bool `cbor:"rk,omitempty"`
	Uv bool `cbor:"uv,omitempty"`
	Up bool `cbor:"up,omitempty"`
}

type HmacSecret *bool

type ExtensionsList struct {
	HmacSecret HmacSecret `cbor:"hmac-secret,omitempty"`
}
type AuthenticatorMakeCredential struct {
	ClientDataHash   []byte                         `cbor:"1,keyasint,omitempty"`
	Rp               *PublicKeyCredentialRpEntity   `cbor:"2,keyasint,omitempty"`
	User             *PublicKeyCredentialUserEntity `cbor:"3,keyasint,omitempty"`
	PubKeyCredParams []*PubKeyCredParamsItem        `cbor:"4,keyasint,omitempty"`
	ExcludeList      []*ExcludeCredential           `cbor:"5,keyasint,omitempty"`
	Extensions       *ExtensionsList                `cbor:"6,keyasint,omitempty"`
	Options          *Options                       `cbor:"7,keyasint,omitempty"`
	PinAuth          []byte                         `cbor:"8,keyasint,omitempty"`
	PinProtocol      uint                           `cbor:"9,keyasint,omitempty"`
}

type AttStmtObject_ES256 struct {
	Alg int      `cbor:"alg"`
	Sig []byte   `cbor:"sig"`
	X5c [][]byte `cbor:"x5c"`
	//EcdaaKeyID string `cbor:"ecdaaKeyId"`
}

type AttestationObjectRaw struct {
	Fmt      string          `cbor:"1,keyasint"`
	AuthData []byte          `cbor:"2,keyasint"`
	AttStmt  cbor.RawMessage `cbor:"3,keyasint"`
}

type AttestationObject struct {
	Fmt      string
	AuthData *AuthenticatorData
	AttStmt  *AttStmtObject_ES256
}

type AttCredDataObject struct {
	Aaguid     []byte //16 byte
	CredIdLen  uint16 //big endian
	CredID     []byte //CredIdLen byte
	CredPubKey *CoseKey
}

type AuthenticatorData struct {
	RpIdHash    []byte //32 byte
	Flags       uint8
	Counter     uint32
	AttCredData *AttCredDataObject
	Extensions  *ExtensionsList
	Raw         []byte
}

// Use cbor.RawMessage to delay unmarshaling (CrvOrNOrK's data type depends on Kty's value).
type CoseKey struct {
	Kty       int    `cbor:"1,keyasint,omitempty"`
	Kid       []byte `cbor:"2,keyasint,omitempty"`
	Alg       int    `cbor:"3,keyasint,omitempty"`
	KeyOpts   int    `cbor:"4,keyasint,omitempty"`
	IV        []byte `cbor:"5,keyasint,omitempty"`
	CrvOrNOrK int    `cbor:"-1,keyasint,omitempty"` // K for symmetric keys, Crv for elliptic curve keys, N for RSA modulus
	XOrE      []byte `cbor:"-2,keyasint,omitempty"` // X for curve x-coordinate, E for RSA public exponent
	Y         []byte `cbor:"-3,keyasint,omitempty"` // Y for curve y-cooridate
	D         []byte `cbor:"-4,keyasint,omitempty"`
}

type SharedSecret struct {
	Publickey_X  []byte
	Publickey_Y  []byte
	SharedSecret []byte
}

func (c *CTAP) MakeCredential(cdh []byte, rp_ID, rp_name string, user_Name, user_DisplayName string, user_ID []byte, pinToken []byte, rk, withHMAC bool) (*AttestationObject, error) {
	if len(cdh) != 32 {
		return nil, fmt.Errorf("cdh must be 32 bytes")
	}
	if withHMAC && !rk {
		return nil, fmt.Errorf("withHMAC and rk must be true at the same time")
	}

	input := make_Credentials(cdh, rp_ID, rp_name, user_Name, user_DisplayName, user_ID, pinToken, rk, withHMAC)
	raw, err := c.send_CBOR(CMD_authenticatorMakeCredential, input)
	if err != nil {
		return nil, err
	}
	return credentialsParser(raw)
}

func credentialsParser(raw []byte) (*AttestationObject, error) {
	var attest AttestationObjectRaw
	err := cbor.Unmarshal(raw, &attest)
	if err != nil {
		return nil, err
	}

	authData, err := parseAttestAuthData(attest.AuthData)
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

func parseAttestAuthData(data []byte) (*AuthenticatorData, error) {
	var auth AuthenticatorData
	auth.Raw = data
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

func make_Credentials(cdh []byte, rp_ID, rp_name string, user_Name, user_DisplayName string, user_ID []byte, pinToken []byte, rk, withHMAC bool) *AuthenticatorMakeCredential {
	_t := new(bool)
	_f := new(bool)

	*_t = true
	*_f = false

	data := &AuthenticatorMakeCredential{
		ClientDataHash: cdh, // mycrypto.GetRandArray(32),
		Rp: &PublicKeyCredentialRpEntity{
			Id:   rp_ID,
			Name: rp_name,
		},
		User: &PublicKeyCredentialUserEntity{
			Id:          user_ID,
			Name:        user_Name,
			DisplayName: user_DisplayName,
		},
		PubKeyCredParams: []*PubKeyCredParamsItem{
			{
				Alg:  -7,
				Type: "public-key",
			},
		},

		Options: &Options{
			Uv: pinToken == nil,
			Rk: rk,
		},
		PinProtocol: 1,
	}
	if pinToken != nil {
		data.PinAuth = hmac_sha256_16(pinToken, cdh)
	}
	if withHMAC {
		data.Extensions = &ExtensionsList{
			HmacSecret: _t,
		}
	}
	return data
}

func getKeyAgreement(secret *SharedSecret) *CoseKey {
	key := &CoseKey{
		Kty:       2,
		Alg:       -25,
		CrvOrNOrK: 1,
		XOrE:      secret.Publickey_X,
		Y:         secret.Publickey_Y,
	}
	return key
}
