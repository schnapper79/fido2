package ctaphid

import (
	"fido2/cbordata/credentials"
	"fmt"
)

const CMD_authenticatorMakeCredential = 0x01

func (c *CTAP) MakeCredential(cdh []byte, rp_ID, rp_name string, user_Name, user_DisplayName string, user_ID []byte, pinToken []byte, rk, withHMAC bool) (*credentials.AttestationObject, error) {
	if len(cdh) != 32 {
		return nil, fmt.Errorf("cdh must be 32 bytes")
	}
	if withHMAC && !rk {
		return nil, fmt.Errorf("withHMAC and rk must be true at the same time")
	}

	input := credentials.Make_Credentials(cdh, rp_ID, rp_name, user_Name, user_DisplayName, user_ID, pinToken, rk, withHMAC)
	raw, err := c.Send_CBOR(CMD_authenticatorMakeCredential, input)
	if err != nil {
		return nil, err
	}
	return credentials.Parser(raw)
}
