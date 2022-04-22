package fido2

import (
	"fido2/cbordata/credentials"
	"fido2/mycrypto"
	"fmt"
)

func Example() {
	fido, err := GetFido2Device()
	if err != nil {
		panic(err)
	}
	fmt.Println("Protocol version:", fido.Info.Protocol_Version)
	fmt.Println("Device version:", fido.Info.Major_Device_Version, ".", fido.Info.Minor_Device_Version, ".", fido.Info.Build_Device_Version)
	fmt.Println("Capabilities:", fido.Info.Capability_flags)
	/*
		infoCBOR, err := fido.CTAP.GetInfoCbor()
		if err != nil {
			panic(err)
		}
		fmt.Printf("Cbor info: %+v\n", infoCBOR)

		pinRetries, err := fido.ClientPIN_GetRetries()
		if err != nil {
			panic(err)
		}
		fmt.Printf("Client PIN retries: %d\n", pinRetries.RetriesLeft)

		KeyAgreement, err := fido.ClientPIN_GetKeyAgreement()
		if err != nil {
			panic(err)
		}
		fmt.Printf("keyAgreement: %x\n", KeyAgreement.KeyAgreement)

		var pin string
		fmt.Println("please enter your pin:")
		fmt.Scanln(&pin)

		pinToken, err := fido.CTAP.ClientPIN_GetPinToken(pin)
		if err != nil {
			panic(err)
		}
		fmt.Printf("pinToken: %x (%d)\n", pinToken.PinToken, len(pinToken.PinToken))
	*/
	cdh := mycrypto.GetRandArray(32)

	rp_id := "localhost"
	rp_name := "my localhost"
	user_name := "me_myself_and_I"
	user_display_name := "me_myself_and_I"
	user_id := mycrypto.GetRandArray(32)

	attest, err := fido.CTAP.MakeCredential(cdh, rp_id, rp_name, user_name, user_display_name, user_id, nil, true, true)
	if err != nil {
		panic(err)
	}
	credentials.PrintAttestationObject(attest)
	fmt.Println("")

	allowedCredIds := make([][]byte, 0)
	allowedCredIds = append(allowedCredIds, attest.AuthData.AttCredData.CredID)

	cdh = mycrypto.GetRandArray(32)
	salt := mycrypto.GetRandArray(32)
	salt2 := mycrypto.GetRandArray(32)

	assert, err := fido.CTAP.GetAssertion(rp_id, cdh, allowedCredIds, nil, true, salt, salt2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("hmac run 1: %x\n\n", assert.AuthData.Extensions.Secret)

	//ToDo: get public Key from credential
	//ToDo: get Signatures for whatever I want....

}
