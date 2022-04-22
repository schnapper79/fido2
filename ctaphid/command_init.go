package ctaphid

import (
	"fido2/mycrypto"
	"fmt"
)

const CMD_INIT uint8 = 0x06

type Capability_flags struct {
	CAPABILITY_WINK  bool
	CAPABILITY_CBOR  bool
	CAPABILITY_NMESG bool
}

type INIT_INFO struct {
	Protocol_Version     uint8
	Major_Device_Version uint8
	Minor_Device_Version uint8
	Build_Device_Version uint8
	Capability_flags     Capability_flags
}

func (c *CTAP) SendInitCommand() (*INIT_INFO, error) {
	if c.dev == nil {
		return nil, fmt.Errorf("fido dev is nil")
	}

	infoRaw, err := c.dev.SendAndReceive(CMD_INIT, mycrypto.GetRandArray(8))
	if err != nil {
		return nil, err
	}

	if len(infoRaw) >= 17 {
		newCid := uint32(infoRaw[8]) | uint32(infoRaw[9])<<8 | uint32(infoRaw[10])<<16 | uint32(infoRaw[11])<<24
		c.dev.SetNewCID(newCid)

		cf := uint16(infoRaw[16]) | uint16(infoRaw[17])<<8
		return &INIT_INFO{
			Protocol_Version:     infoRaw[12],
			Major_Device_Version: infoRaw[13],
			Minor_Device_Version: infoRaw[14],
			Build_Device_Version: infoRaw[15],
			Capability_flags: Capability_flags{
				CAPABILITY_WINK:  cf&0x01 == 0x01,
				CAPABILITY_CBOR:  cf&0x04 == 0x04,
				CAPABILITY_NMESG: cf&0x08 == 0x08,
			},
		}, nil
	}
	return nil, fmt.Errorf("INIT error")

}
