package ctaphid

import (
	"fido2/cbordata/credentials"
	"fido2/cbordata/pin"
)

func (c *CTAP) ClientPIN_GetRetries() (*pin.AuthenticatorClientPIN_Answer, error) {
	raw, err := c.Send_CBOR(pin.CMD_authenticatorClientPIN, pin.GetPinSubcommand(pin.CMD_authenticator_subCommand_getRetries, nil, nil, nil, nil))
	if err != nil {
		return nil, err
	}
	return pin.Parser(raw, nil)
}

func (c *CTAP) ClientPIN_GetKeyAgreement() (*pin.AuthenticatorClientPIN_Answer, error) {
	raw, err := c.Send_CBOR(pin.CMD_authenticatorClientPIN, pin.GetPinSubcommand(pin.CMD_authenticator_subCommand_getKeyAgreement, nil, nil, nil, nil))
	if err != nil {
		return nil, err
	}
	return pin.Parser(raw, nil)
}

func (c *CTAP) ClientPIN_Set(newPin string) (*pin.AuthenticatorClientPIN_Answer, error) {
	secret, err := c.MakeSharedSecret()
	if err != nil {
		return nil, err
	}

	newPinEnc, err := pin.EncryptPin([]byte(newPin), secret)
	if err != nil {
		return nil, err
	}

	key := pin.GetKeyAgreement(secret)

	raw, err := c.Send_CBOR(pin.CMD_authenticatorClientPIN, pin.GetPinSubcommand(pin.CMD_authenticator_subCommand_setPin, key, newPinEnc, nil, nil))
	if err != nil {
		return nil, err
	}

	return pin.Parser(raw, nil)
}

func (c *CTAP) ClientPIN_GetPinToken(curPin string) (*pin.AuthenticatorClientPIN_Answer, error) {
	secret, err := c.MakeSharedSecret()
	if err != nil {
		return nil, err
	}
	key := pin.GetKeyAgreement(secret)

	hashPin := pin.HashPin(curPin)
	encPin := pin.EncryptHashedPin(hashPin, secret)
	raw, err := c.Send_CBOR(pin.CMD_authenticatorClientPIN, pin.GetPinSubcommand(pin.CMD_authenticator_subCommand_getPinToken, key, nil, nil, encPin))
	if err != nil {
		return nil, err
	}

	return pin.Parser(raw, secret)
}

func (c *CTAP) MakeSharedSecret() (*credentials.SharedSecret, error) {
	keyAgreement, err := c.ClientPIN_GetKeyAgreement()
	if err != nil {
		return nil, err
	}
	return pin.MakeSharedSecret(keyAgreement.KeyAgreement)
}
