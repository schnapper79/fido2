package fido2

import "github.com/fxamacker/cbor/v2"

const CMD_authenticatorGetInfo = 0x04

type AuthenticatorGetInfo struct {
	Versions     []string        `cbor:"1,keyasint"`
	Extensions   []string        `cbor:"2,keyasint"`
	Aaguid       []byte          `cbor:"3,keyasint"`
	Options      map[string]bool `cbor:"4,keyasint"`
	MaxMsgSize   uint            `cbor:"5,keyasint"`
	PinProtocols []uint          `cbor:"6,keyasint"`
}

func (c *CTAP) GetInfoCbor() (*AuthenticatorGetInfo, error) {
	raw, err := c.send_CBOR(CMD_authenticatorGetInfo, nil)
	if err != nil {
		return nil, err
	}
	return infoParser(raw)
}

func infoParser(raw []byte) (*AuthenticatorGetInfo, error) {
	var info AuthenticatorGetInfo
	err := cbor.Unmarshal(raw, &info)
	if err != nil {
		return nil, err
	}
	return &info, nil
}
