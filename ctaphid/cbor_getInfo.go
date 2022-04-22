package ctaphid

import (
	"fido2/cbordata/info"
)

func (c *CTAP) GetInfoCbor() (*info.AuthenticatorGetInfo, error) {
	raw, err := c.Send_CBOR(info.CMD_authenticatorGetInfo, nil)
	if err != nil {
		return nil, err
	}
	return info.Parser(raw)
}
