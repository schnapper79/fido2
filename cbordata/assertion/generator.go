package assertion

import (
	"fido2/cbordata/credentials"
	"fido2/mycrypto"
)

func GetAssertionRequest(rpid string, cdh []byte, allowList [][]byte, pinAuth []byte, withHMAC bool, sharedSecret *credentials.SharedSecret, salt1 []byte, salt2 []byte) *AssertionRequestObject {
	data := &AssertionRequestObject{
		RPID:           rpid,
		ClientDataHash: cdh,
		//AllowList:      nil,
		Options: &credentials.Options{
			Uv: pinAuth == nil,
			Up: true,
		},
		PinProtocol: 1,
	}
	if pinAuth != nil {
		data.PinAuth = mycrypto.Hmac_sha256_16(pinAuth, cdh)
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
			HmacSecret: GetHmacSecretRequest(sharedSecret, salt1, salt2),
		}
	}

	return data
}

func GetHmacSecretRequest(sharedSecret *credentials.SharedSecret, salt1, salt2 []byte) *HmacSecretRequest {
	key := credentials.GetKeyAgreement(sharedSecret)
	salt := salt1[:]
	if (salt2 != nil) && (len(salt2) == 32) {
		salt = append(salt, salt2...)
	}

	saltEnc := mycrypto.Aes256_Enc(salt, sharedSecret.SharedSecret, 32)
	saltAuth := mycrypto.Hmac_sha256_16(sharedSecret.SharedSecret, saltEnc)

	return &HmacSecretRequest{
		KeyAgreement: key,
		SaltEnc:      saltEnc,
		SaltAuth:     saltAuth,
	}
}
