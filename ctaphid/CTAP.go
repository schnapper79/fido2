package ctaphid

import "fido2/hidraw"

type CTAP struct {
	dev *hidraw.HidDevice
}

func (c *CTAP) SetDevice(dev *hidraw.HidDevice) {
	c.dev = dev
}
