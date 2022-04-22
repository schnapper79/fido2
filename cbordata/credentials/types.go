package credentials

import "github.com/fxamacker/cbor/v2"

type PublicKeyCredentialRpEntity struct {
	Name string `cbor:"name"`
	Id   string `cbor:"id"`
}
type PublicKeyCredentialUserEntity struct {
	Id          []byte `cbor:"id"`
	Icon        string `cbor:"icon,omitempty"`
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
