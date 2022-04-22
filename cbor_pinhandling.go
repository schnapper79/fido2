package fido2

import (
	"github.com/fxamacker/cbor/v2"
)

const (
	CMD_authenticatorClientPIN                   = 0x06
	CMD_authenticator_subCommand_getRetries      = 0x01
	CMD_authenticator_subCommand_getKeyAgreement = 0x02
	CMD_authenticator_subCommand_setPin          = 0x03
	CMD_authenticator_subCommand_changePin       = 0x04
	CMD_authenticator_subCommand_getPinToken     = 0x05
)

type AuthenticatorClientPIN struct {
	PinProtocol  uint     `cbor:"1,keyasint"`
	SubCommand   uint     `cbor:"2,keyasint"`
	KeyAgreement *CoseKey `cbor:"3,keyasint,omitempty"`
	PinAuth      []byte   `cbor:"4,keyasint,omitempty"`
	NewPinEnc    []byte   `cbor:"5,keyasint,omitempty"`
	PinHashEnc   []byte   `cbor:"6,keyasint,omitempty"`
}

type AuthenticatorClientPIN_Answer struct {
	KeyAgreement *CoseKey `cbor:"1,keyasint"`
	PinToken     []byte   `cbor:"2,keyasint"`
	RetriesLeft  uint     `cbor:"3,keyasint"`
}

func (c *CTAP) ClientPIN_GetRetries() (*AuthenticatorClientPIN_Answer, error) {
	raw, err := c.send_CBOR(CMD_authenticatorClientPIN, getPinSubcommand(CMD_authenticator_subCommand_getRetries, nil, nil, nil, nil))
	if err != nil {
		return nil, err
	}
	return pinParser(raw, nil)
}

func (c *CTAP) ClientPIN_GetKeyAgreement() (*AuthenticatorClientPIN_Answer, error) {
	raw, err := c.send_CBOR(CMD_authenticatorClientPIN, getPinSubcommand(CMD_authenticator_subCommand_getKeyAgreement, nil, nil, nil, nil))
	if err != nil {
		return nil, err
	}
	return pinParser(raw, nil)
}

func (c *CTAP) ClientPIN_Set(newPin string) (*AuthenticatorClientPIN_Answer, error) {
	secret, err := c.MakeSharedSecret()
	if err != nil {
		return nil, err
	}

	newPinEnc, err := encryptPin([]byte(newPin), secret)
	if err != nil {
		return nil, err
	}

	key := getKeyAgreement(secret)

	raw, err := c.send_CBOR(CMD_authenticatorClientPIN, getPinSubcommand(CMD_authenticator_subCommand_setPin, key, newPinEnc, nil, nil))
	if err != nil {
		return nil, err
	}

	return pinParser(raw, nil)
}

func (c *CTAP) ClientPIN_GetPinToken(curPin string) (*AuthenticatorClientPIN_Answer, error) {
	secret, err := c.MakeSharedSecret()
	if err != nil {
		return nil, err
	}
	key := getKeyAgreement(secret)

	hashPin := hashPin(curPin)
	encPin := encryptHashedPin(hashPin, secret)
	raw, err := c.send_CBOR(CMD_authenticatorClientPIN, getPinSubcommand(CMD_authenticator_subCommand_getPinToken, key, nil, nil, encPin))
	if err != nil {
		return nil, err
	}

	return pinParser(raw, secret)
}

func (c *CTAP) MakeSharedSecret() (*SharedSecret, error) {
	keyAgreement, err := c.ClientPIN_GetKeyAgreement()
	if err != nil {
		return nil, err
	}
	return makeSharedSecret(keyAgreement.KeyAgreement)
}

func pinParser(raw []byte, secret *SharedSecret) (*AuthenticatorClientPIN_Answer, error) {
	var info AuthenticatorClientPIN_Answer
	err := cbor.Unmarshal(raw, &info)
	if err != nil {
		return nil, err
	}

	if info.PinToken != nil && len(info.PinToken)%16 == 0 {
		info.PinToken, err = aes256_Dec(info.PinToken, secret.SharedSecret)
		if err != nil {
			return nil, err
		}
	}
	return &info, nil
}

func getPinSubcommand(subcommand uint, keyAgreement *CoseKey, pinAuth, newPinEnc, pinHashEnc []byte) *AuthenticatorClientPIN {
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
func encryptPin(pin []byte, secret *SharedSecret) ([]byte, error) {
	return nil, nil
}

func makeSharedSecret(in *CoseKey) (*SharedSecret, error) {
	sharedSecret, pubKey := getSharedSecret(in.XOrE, in.Y)
	out := &SharedSecret{
		SharedSecret: sharedSecret,
		Publickey_X:  pubKey.X.Bytes(),
		Publickey_Y:  pubKey.Y.Bytes(),
	}
	return out, nil
}
func hashPin(curPin string) []byte {
	return sha256_16(curPin)
}
func encryptHashedPin(hash []byte, sharedSecret *SharedSecret) []byte {
	return aes256_Enc(hash, sharedSecret.SharedSecret, 16)
}
