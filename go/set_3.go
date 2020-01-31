package cryptopals

import (
	"fmt"
	mathrand "math/rand"
)

func cbcPaddingOracles() (
	encryptionOracle func() (ciphertext []byte, iv []byte),
	paddingOracle func([]byte, []byte) bool) {
	list := [10]string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"}

	encryptionKey := generateRandomBytes(16)

	encryptionOracle = func() (ciphertext []byte, iv []byte) {
		ptxt := decodeBase64(list[mathrand.Intn(len(list))])
		fmt.Println(ptxt)
		//iv = generateRandomBytes(16)
		iv = make([]byte, 16)
		ciphertext = aesCbcEncrypt(pkcs7Padding([]byte(ptxt), 16), encryptionKey, iv)
		return
	}
	paddingOracle = func(ciphertext []byte, iv []byte) bool {
		ptxt, _ := pkcs7UnPadding(aesCbcDecrypt(ciphertext, encryptionKey, iv))
		if ptxt != nil {
			return true
		}
		return false
	}
	return
}
