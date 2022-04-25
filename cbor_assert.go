package fido2

import (
	"bytes"

	"github.com/fxamacker/cbor/v2"
)

const (
	CMD_authenticatorGetAssertion     = 0x02
	CMD_authenticatorGetNextAssertion = 0x08
)

type PublicKeyCredentialDescriptor struct {
	Type string `cbor:"type"` // "public-key"
	Id   []byte `cbor:"id"`   //credential ID (from attestation)
}

type HmacSecretRequest struct {
	KeyAgreement *CoseKey `cbor:"1,keyasint,omitempty"`
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
	Options        *Options                         `cbor:"5,keyasint,omitempty"`
	PinAuth        []byte                           `cbor:"6,keyasint,omitempty"`
	PinProtocol    uint                             `cbor:"7,keyasint,omitempty"`
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
	AttCredData *AttCredDataObject
	Extensions  *ExtensionsListReply
}
type AssertionReplyObjectParsed struct {
	Credential          *PublicKeyCredentialDescriptor
	AuthData            *AuthData
	Signature           []byte
	User                *PublicKeyCredentialUserEntity
	NumberOfCredentials uint
	AuthDataRaw         []byte
}

func (c *CTAP) GetAssertion(rpId string, cdh []byte, allowList [][]byte, pinAuth []byte, withHMAC bool, salt1 []byte, salt2 []byte) (*AssertionReplyObjectParsed, error) {
	//GetSharedSecret()
	sharedSecret, err := c.MakeSharedSecret()
	if err != nil {
		return nil, err
	}

	assertionRequest := getAssertionRequest(rpId, cdh, allowList, pinAuth, withHMAC, sharedSecret, salt1, salt2)
	raw, err := c.send_CBOR(CMD_authenticatorGetAssertion, assertionRequest)
	if err != nil {
		return nil, err
	}

	assertionReply, err := assertionParser(raw, sharedSecret.SharedSecret)
	if err != nil {
		return nil, err
	}

	return assertionReply, nil
}

func assertionParser(raw []byte, sharedSecret []byte) (*AssertionReplyObjectParsed, error) {
	var assert AssertionReplyObjectRaw
	err := cbor.Unmarshal(raw, &assert)
	if err != nil {
		return nil, err
	}

	authData, err := parseAssertAuthData(assert.AuthData)
	if err != nil {
		return nil, err
	}

	out := &AssertionReplyObjectParsed{
		Credential:          assert.Credential,
		AuthData:            authData,
		Signature:           assert.Signature,
		User:                assert.User,
		NumberOfCredentials: assert.NumberOfCredentials,
		AuthDataRaw:         assert.AuthData,
	}

	if (out.AuthData.Extensions != nil) && (out.AuthData.Extensions.HmacSecret != nil) && (len(out.AuthData.Extensions.HmacSecret)) > 0 {
		//have one salt:
		out.AuthData.Extensions.Secret, err = aes256_Dec(out.AuthData.Extensions.HmacSecret, sharedSecret)
		if err != nil {
			return nil, err
		}
	}
	return out, nil

}

func parseAssertAuthData(data []byte) (*AuthData, error) {
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

func getAssertionRequest(rpid string, cdh []byte, allowList [][]byte, pinAuth []byte, withHMAC bool, sharedSecret *SharedSecret, salt1 []byte, salt2 []byte) *AssertionRequestObject {
	data := &AssertionRequestObject{
		RPID:           rpid,
		ClientDataHash: cdh,
		//AllowList:      nil,
		Options: &Options{
			Uv: pinAuth == nil,
			Up: true,
		},
		PinProtocol: 1,
	}
	if pinAuth != nil {
		data.PinAuth = hmac_sha256_16(pinAuth, cdh)
	}
	if (allowList != nil) && (len(allowList) > 0) {
		data.AllowList = make([]*PublicKeyCredentialDescriptor, 0)
		for _, v := range allowList {
			if v != nil {
				item := &PublicKeyCredentialDescriptor{
					Id:   v,
					Type: "public-key",
				}
				data.AllowList = append(data.AllowList, item)
			}
		}
	}

	if withHMAC && sharedSecret != nil && salt1 != nil {
		data.Extensions = &ExtensionsListRequest{
			HmacSecret: getHmacSecretRequest(sharedSecret, salt1, salt2),
		}
	}

	return data
}

func getHmacSecretRequest(sharedSecret *SharedSecret, salt1, salt2 []byte) *HmacSecretRequest {
	key := getKeyAgreement(sharedSecret)
	salt := salt1[:]
	if (salt2 != nil) && (len(salt2) == 32) {
		salt = append(salt, salt2...)
	}

	saltEnc := aes256_Enc(salt, sharedSecret.SharedSecret, 32)
	saltAuth := hmac_sha256_16(sharedSecret.SharedSecret, saltEnc)

	return &HmacSecretRequest{
		KeyAgreement: key,
		SaltEnc:      saltEnc,
		SaltAuth:     saltAuth,
	}
}
