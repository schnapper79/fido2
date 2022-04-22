package fido2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

func getSharedSecret(x, y []byte) ([]byte, *ecdsa.PublicKey) {
	private, px, py, _ := elliptic.GenerateKey(elliptic.P256(), rand.Reader)

	var pubb_x, pubb_y big.Int
	pubb_x = *pubb_x.SetBytes(x)
	pubb_y = *pubb_y.SetBytes(y)

	a, _ := elliptic.P256().ScalarMult(&pubb_x, &pubb_y, private)
	shared1 := sha256.Sum256(a.Bytes())
	return shared1[:], &ecdsa.PublicKey{elliptic.P256(), px, py}
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
