package fido2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// getSharedSecret runs the platform side of CTAP2 PIN protocol 1: a fresh
// P-256 key, ECDH with the authenticator's key-agreement point (x, y), and
// SHA-256 over the 32-byte x coordinate of the product.
//
// The point comes off the USB bus and is validated before use (on the curve,
// not the point at infinity, coordinates of exactly 32 bytes): an unchecked
// point let whoever sits on the bus force the shared secret and read the PIN,
// the PIN token and every hmac-secret output. crypto/ecdh also keeps the
// leading zero bytes that big.Int.Bytes() dropped — the old code hashed a
// shortened x (and sent a shortened platform key) about once in 256 runs, which
// looked like a wrong PIN.
func getSharedSecret(x, y []byte) (shared, platformX, platformY []byte, err error) {
	if len(x) != 32 || len(y) != 32 {
		return nil, nil, nil, fmt.Errorf("fido2: key agreement point must have 32-byte coordinates (got %d, %d)", len(x), len(y))
	}
	peer, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fido2: invalid key agreement point: %w", err)
	}
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	z, err := priv.ECDH(peer)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fido2: ECDH: %w", err)
	}
	sum := sha256.Sum256(z)
	pub := priv.PublicKey().Bytes() // 0x04 || X(32) || Y(32)
	return sum[:], pub[1:33], pub[33:65], nil
}

func aes256_Enc(bPlaintext []byte, bKey []byte, lmin int) []byte {
	for len(bPlaintext) < lmin {
		bPlaintext = append(bPlaintext, 0)
	}

	block, _ := aes.NewCipher(bKey)
	bIV := make([]byte, aes.BlockSize)
	ciphertext := make([]byte, len(bPlaintext))
	mode := cipher.NewCBCEncrypter(block, bIV)
	mode.CryptBlocks(ciphertext, bPlaintext)
	return ciphertext
}

func aes256_Dec(cipherText, bKey []byte) ([]byte, error) {

	bIV := make([]byte, aes.BlockSize)

	block, err := aes.NewCipher(bKey)
	if err != nil {
		return nil, err
	}
	res := make([]byte, len(cipherText))
	mode := cipher.NewCBCDecrypter(block, bIV)
	mode.CryptBlocks(res, cipherText)

	return res, nil
}

func hmac_sha256_16(bKey []byte, bPlaintext []byte) []byte {
	mac := hmac.New(sha256.New, bKey)
	mac.Write(bPlaintext)
	return mac.Sum(nil)[:16]
}
func sha256_16(plaintext string) []byte {
	bPlaintext := []byte(plaintext)
	res := sha256.Sum256(bPlaintext)
	return res[:16]
}

func GetRandArray(size int) []byte {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}
