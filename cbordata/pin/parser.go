package pin

import (
	"fido2/cbordata/credentials"
	"fido2/mycrypto"

	"github.com/fxamacker/cbor/v2"
)

func Parser(raw []byte, secret *credentials.SharedSecret) (*AuthenticatorClientPIN_Answer, error) {
	var info AuthenticatorClientPIN_Answer
	err := cbor.Unmarshal(raw, &info)
	if err != nil {
		return nil, err
	}

	if info.PinToken != nil && len(info.PinToken)%16 == 0 {
		info.PinToken, err = mycrypto.Aes256_Dec(info.PinToken, secret.SharedSecret)
		if err != nil {
			return nil, err
		}
	}
	return &info, nil
}
