package mycrypto_test

import (
	"fido2/mycrypto"
	"testing"
)

func Test_Aes(t *testing.T) {
	secret := mycrypto.GetRandArray(16)
	testdata := mycrypto.GetRandArray(64)

	ciphertext := mycrypto.Aes256_Enc(testdata, secret, 32)
	plaintext, err := mycrypto.Aes256_Dec(ciphertext, secret)

	if err != nil {
		t.Error(err)
	}

	if len(plaintext) != len(testdata) {
		t.Error("plaintext length is not equal to testdata length")
	}

	for i, b := range plaintext {
		if b != testdata[i] {
			t.Errorf("plaintext[%d](%x) is not equal to testdata[%d](%x)", i, b, i, testdata[i])
		}
	}
}

func Test_HMAC(t *testing.T) {
	secret := mycrypto.GetRandArray(32)
	data := mycrypto.GetRandArray(64)
	hmac := mycrypto.Hmac_sha256_16(secret, data)
	if len(hmac) != 16 {
		t.Error("hmac length is not equal to 16")
	}

}
