package fido2

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func Test_Aes(t *testing.T) {
	secret := GetRandArray(16)
	testdata := GetRandArray(64)

	ciphertext := aes256_Enc(testdata, secret, 32)
	plaintext, err := aes256_Dec(ciphertext, secret)

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
	secret := GetRandArray(32)
	data := GetRandArray(64)
	hmac := hmac_sha256_16(secret, data)
	if len(hmac) != 16 {
		t.Error("hmac length is not equal to 16")
	}

}

// Test_SharedSecretRejectsPointsOffTheCurve — the key-agreement point comes
// off the USB bus. An unchecked point let whoever sits on the bus force the
// shared secret and read the PIN, the PIN token and the hmac-secret output.
func Test_SharedSecretRejectsPointsOffTheCurve(t *testing.T) {
	good, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := good.PublicKey().Bytes()
	x, y := pub[1:33], pub[33:65]

	shared, px, py, err := getSharedSecret(x, y)
	if err != nil {
		t.Fatalf("a valid point was refused: %v", err)
	}
	if len(shared) != 32 || len(px) != 32 || len(py) != 32 {
		t.Fatalf("lengths shared=%d x=%d y=%d, want 32 each", len(shared), len(px), len(py))
	}
	// Both sides must derive the same secret: SHA-256 over the full x.
	peer, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, px...), py...))
	if err != nil {
		t.Fatal(err)
	}
	z, err := good.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256(z); !bytes.Equal(shared, want[:]) {
		t.Error("platform and authenticator derive different secrets")
	}

	offCurve := append([]byte(nil), y...)
	offCurve[31] ^= 1
	if _, _, _, err := getSharedSecret(x, offCurve); err == nil {
		t.Error("a point off the curve was accepted")
	}
	zero := make([]byte, 32)
	if _, _, _, err := getSharedSecret(zero, zero); err == nil {
		t.Error("the point (0,0) was accepted")
	}
	if _, _, _, err := getSharedSecret(x[1:], y); err == nil {
		t.Error("a 31-byte coordinate was accepted")
	}
	if _, err := makeSharedSecret(nil); err == nil {
		t.Error("a missing key agreement was accepted")
	}
}
