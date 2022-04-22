package info

const CMD_authenticatorGetInfo = 0x04

type AuthenticatorGetInfo struct {
	Versions     []string        `cbor:"1,keyasint"`
	Extensions   []string        `cbor:"2,keyasint"`
	Aaguid       []byte          `cbor:"3,keyasint"`
	Options      map[string]bool `cbor:"4,keyasint"`
	MaxMsgSize   uint            `cbor:"5,keyasint"`
	PinProtocols []uint          `cbor:"6,keyasint"`
}
