package info

import "github.com/fxamacker/cbor/v2"

func Parser(raw []byte) (*AuthenticatorGetInfo, error) {
	var info AuthenticatorGetInfo
	err := cbor.Unmarshal(raw, &info)
	if err != nil {
		return nil, err
	}
	return &info, nil

}
