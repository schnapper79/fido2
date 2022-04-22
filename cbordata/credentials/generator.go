package credentials

import "fido2/mycrypto"

func Make_Credentials(cdh []byte, rp_ID, rp_name string, user_Name, user_DisplayName string, user_ID []byte, pinToken []byte, rk, withHMAC bool) *AuthenticatorMakeCredential {
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
		data.PinAuth = mycrypto.Hmac_sha256_16(pinToken, cdh)
	}
	if withHMAC {
		data.Extensions = &ExtensionsList{
			HmacSecret: _t,
		}
	}
	return data
}

func GetKeyAgreement(secret *SharedSecret) *CoseKey {
	key := &CoseKey{
		Kty:       2,
		Alg:       -25,
		CrvOrNOrK: 1,
		XOrE:      secret.Publickey_X,
		Y:         secret.Publickey_Y,
	}
	return key
}
