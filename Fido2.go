package fido2

type FIDO2 struct {
	CTAP *CTAP
	Info *INIT_INFO
}

func GetFido2Device() (*FIDO2, error) {
	dev, err := findFIDO()
	if err != nil {
		return nil, err
	}
	rst := &FIDO2{CTAP: &CTAP{}}
	rst.CTAP.SetDevice(dev)

	rst.Info, err = rst.CTAP.SendInitCommand()
	if err != nil {
		panic(err)
	}
	return rst, nil
}
