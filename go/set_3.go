package cryptopals

import mathrand "math/rand"

func cbcPaddingOracleEncryption() (
	encryptionOracle func([]byte) (ciphertext []byte, iv []byte),
	decryptionOracle func([]byte, []byte) bool) {
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

	encryptionOracle = func(in []byte) (ciphertext []byte, iv []byte) {
		ptxt := list[mathrand.Intn(9)]
		iv = generateRandomBytes(16)
		ciphertext = aesCbcEncrypt(pkcs7Padding([]byte(ptxt), 16), encryptionKey, iv)
		return
	}
	decryptionOracle = func(ciphertext []byte, iv []byte) bool {
		ptxt := aesCbcDecrypt(ciphertext, encryptionKey, iv)
		_, err := pkcs7UnPadding(ptxt)
		if err != nil {
			return false
		}
		return true
	}
	return
}
