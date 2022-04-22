package pin

import (
	"fido2/cbordata/credentials"
	"fido2/mycrypto"
)

func GetPinSubcommand(subcommand uint, keyAgreement *credentials.CoseKey, pinAuth, newPinEnc, pinHashEnc []byte) *AuthenticatorClientPIN {
	cdata := &AuthenticatorClientPIN{
		PinProtocol:  1,
		SubCommand:   subcommand,
		KeyAgreement: keyAgreement,
		PinAuth:      pinAuth,
		NewPinEnc:    newPinEnc,
		PinHashEnc:   pinHashEnc,
	}
	return cdata
}
func EncryptPin(pin []byte, secret *credentials.SharedSecret) ([]byte, error) {
	return nil, nil
}

func GetKeyAgreement(secret *credentials.SharedSecret) *credentials.CoseKey {
	return credentials.GetKeyAgreement(secret)
}

func MakeSharedSecret(in *credentials.CoseKey) (*credentials.SharedSecret, error) {
	sharedSecret, pubKey := mycrypto.GetSharedSecret(in.XOrE, in.Y)
	out := &credentials.SharedSecret{
		SharedSecret: sharedSecret,
		Publickey_X:  pubKey.X.Bytes(),
		Publickey_Y:  pubKey.Y.Bytes(),
	}
	return out, nil
}
func HashPin(curPin string) []byte {
	return mycrypto.Sha256_16(curPin)
}
func EncryptHashedPin(hash []byte, sharedSecret *credentials.SharedSecret) []byte {
	return mycrypto.Aes256_Enc(hash, sharedSecret.SharedSecret, 16)
}
