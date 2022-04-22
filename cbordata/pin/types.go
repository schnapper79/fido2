package pin

import (
	"fido2/cbordata/credentials"
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
	PinProtocol  uint                 `cbor:"1,keyasint"`
	SubCommand   uint                 `cbor:"2,keyasint"`
	KeyAgreement *credentials.CoseKey `cbor:"3,keyasint,omitempty"`
	PinAuth      []byte               `cbor:"4,keyasint,omitempty"`
	NewPinEnc    []byte               `cbor:"5,keyasint,omitempty"`
	PinHashEnc   []byte               `cbor:"6,keyasint,omitempty"`
}

type AuthenticatorClientPIN_Answer struct {
	KeyAgreement *credentials.CoseKey `cbor:"1,keyasint"`
	PinToken     []byte               `cbor:"2,keyasint"`
	RetriesLeft  uint                 `cbor:"3,keyasint"`
}
