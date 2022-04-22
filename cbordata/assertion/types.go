package assertion

import "fido2/cbordata/credentials"

const (
	CMD_authenticatorGetAssertion     = 0x02
	CMD_authenticatorGetNextAssertion = 0x08
)

type PublicKeyCredentialDescriptor struct {
	Type string `cbor:"type"` // "public-key"
	Id   []byte `cbor:"id"`   //credential ID (from attestation)
}

type HmacSecretRequest struct {
	KeyAgreement *credentials.CoseKey `cbor:"1,keyasint,omitempty"`
	//publicKey used for shared Secret (CBOR Encoded 1:2,3:-25,-1:1,-2:x,-3:y)
	SaltEnc []byte `cbor:"2,keyasint,omitempty"`
	/*saltEnc(0x02): Encrypt one or two salts (Called salt1 (32 bytes) and salt2 (32 bytes))
	using sharedSecret as follows:
	One salt case: AES256-CBC(sharedSecret, IV=0, salt1 (32 bytes)).
	Two salt case: AES256-CBC(sharedSecret, IV=0, salt1 (32 bytes) || salt2 (32 bytes)).
	*/
	SaltAuth []byte `cbor:"3,keyasint,omitempty"`
	//saltAuth(0x03): LEFT(HMAC-SHA-256(sharedSecret, saltEnc), 16).
}

type ExtensionsListRequest struct {
	HmacSecret *HmacSecretRequest `cbor:"hmac-secret,omitempty"`
}

type ExtensionsListReply struct {
	HmacSecret []byte `cbor:"hmac-secret,omitempty"`
	Secret     []byte `cbor:"-"`
}

type AssertionRequestObject struct {
	RPID           string                           `cbor:"1,keyasint"`
	ClientDataHash []byte                           `cbor:"2,keyasint"`
	AllowList      []*PublicKeyCredentialDescriptor `cbor:"3,keyasint,omitempty"`
	Extensions     *ExtensionsListRequest           `cbor:"4,keyasint,omitempty"`
	Options        *credentials.Options             `cbor:"5,keyasint,omitempty"`
	PinAuth        []byte                           `cbor:"6,keyasint,omitempty"`
	PinProtocol    uint                             `cbor:"7,keyasint,omitempty"`
}
type PublicKeyCredentialUserEntity struct {
	ID          []byte `cbor:"id"`
	Name        string `cbor:"name"`
	DisplayName string `cbor:"displayName"`
}
type AssertionReplyObjectRaw struct {
	Credential          *PublicKeyCredentialDescriptor `cbor:"1,keyasint"`
	AuthData            []byte                         `cbor:"2,keyasint"`
	Signature           []byte                         `cbor:"3,keyasint"`
	User                *PublicKeyCredentialUserEntity `cbor:"4,keyasint"`
	NumberOfCredentials uint                           `cbor:"5,keyasint"`
}
type AuthData struct {
	RpIdHash    []byte //32 byte
	Flags       uint8
	Counter     uint32
	AttCredData *credentials.AttCredDataObject
	Extensions  *ExtensionsListReply
}
type AssertionReplyObjectParsed struct {
	Credential          *PublicKeyCredentialDescriptor
	AuthData            *AuthData
	Signature           []byte
	User                *PublicKeyCredentialUserEntity
	NumberOfCredentials uint
}
