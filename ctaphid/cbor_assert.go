package ctaphid

import (
	"fido2/cbordata/assertion"
)

func (c *CTAP) GetAssertion(rpId string, cdh []byte, allowList [][]byte, pinAuth []byte, withHMAC bool, salt1 []byte, salt2 []byte) (*assertion.AssertionReplyObjectParsed, error) {
	//GetSharedSecret()
	sharedSecret, err := c.MakeSharedSecret()
	if err != nil {
		return nil, err
	}

	assertionRequest := assertion.GetAssertionRequest(rpId, cdh, allowList, pinAuth, withHMAC, sharedSecret, salt1, salt2)
	raw, err := c.Send_CBOR(assertion.CMD_authenticatorGetAssertion, assertionRequest)
	if err != nil {
		return nil, err
	}

	assertionReply, err := assertion.Parser(raw, sharedSecret.SharedSecret)
	if err != nil {
		return nil, err
	}

	return assertionReply, nil
}
