package fido2

import (
	"fido2/ctaphid"
	"fido2/hidraw"
)

type FIDO2 struct {
	CTAP *ctaphid.CTAP
	Info *ctaphid.INIT_INFO
}

func GetFido2Device() (*FIDO2, error) {
	dev, err := hidraw.FindFIDO()
	if err != nil {
		return nil, err
	}
	rst := &FIDO2{CTAP: &ctaphid.CTAP{}}
	rst.CTAP.SetDevice(dev)

	rst.Info, err = rst.CTAP.SendInitCommand()
	if err != nil {
		panic(err)
	}
	return rst, nil
}
