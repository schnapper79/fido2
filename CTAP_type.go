package fido2

type CTAP struct {
	dev *hidDevice
}

func (c *CTAP) SetDevice(dev *hidDevice) {
	c.dev = dev
}
