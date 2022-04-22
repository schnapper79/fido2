package ctaphid

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const CMD_CBOR uint8 = 0x10

type CBOR_MSG struct {
	CTAP_COMMAND uint8
	CTAP_STATUS  uint8
	CBOR_DATA    []byte //already encoded
}

func (c *CBOR_MSG) toByte() []byte {
	var out []byte
	out = append(out, byte(c.CTAP_COMMAND))
	out = append(out, c.CBOR_DATA...)
	return out
}
func (c *CBOR_MSG) fromByte(in []byte) {
	c.CTAP_STATUS = in[0]
	if len(in) > 1 {
		c.CBOR_DATA = in[1:]
	}
}

func (c *CTAP) Send_CBOR(cmd uint8, data interface{}) ([]byte, error) {
	msg := &CBOR_MSG{
		CTAP_COMMAND: cmd,
	}
	encoder, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	if data != nil {
		msg.CBOR_DATA, err = encoder.Marshal(data)
	}
	if err != nil {
		return nil, err
	}

	if c.dev == nil {
		return nil, fmt.Errorf("fido dev is nil")
	}

	answer, err := c.dev.SendAndReceive(CMD_CBOR, msg.toByte())
	if err != nil {
		return nil, err
	}
	var cbor_msg CBOR_MSG
	cbor_msg.fromByte(answer)
	if cbor_msg.CTAP_STATUS != 0 {
		return nil, fmt.Errorf("status not 0x00, 0x%x", cbor_msg.CTAP_STATUS)
	}
	return cbor_msg.CBOR_DATA, nil
}
