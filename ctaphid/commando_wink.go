package ctaphid

const CMD_WINK uint8 = 0x08

func (c *CTAP) Wink() error {
	_, err := c.dev.SendAndReceive(CMD_WINK, nil)
	return err
}
