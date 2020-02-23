package cryptopals

import (
	"crypto/aes"
	"encoding/binary"
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
		iv = generateRandomBytes(16)
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

func attackCbcPaddingOracle(ctxt []byte, paddingOracle func([]byte, []byte) bool) []byte {

	getPtxtBytes := func(foundBytes []byte) []byte {
		ct := make([]byte, 32)
		ptxt := append([]byte{0}, foundBytes...)

		for ptxtGuess := 0; ptxtGuess < 256; ptxtGuess++ {

			copy(ct, ctxt)
			for i := 1; i <= len(foundBytes); i++ {
				ct[len(ct)-16-i] ^= byte(len(foundBytes)+1) ^ byte(foundBytes[len(foundBytes)-i])
			}

			ct[len(ct)-16-(len(foundBytes)+1)] ^= byte(len(foundBytes)+1) ^ byte(ptxtGuess)
			if paddingOracle(ct[16:], ct[0:16]) && (byte(ptxtGuess)^byte(1) != byte(0)) {
				ptxt[0] = byte(ptxtGuess)
			}
		}
		return ptxt
	}
	var ptxt []byte
	for i := 0; i < 16; i++ {
		ptxt = getPtxtBytes(ptxt)
	}

	return ptxt
}

func aesCtrEncrypt(ptxt []byte, passphrase []byte, nonce []byte) []byte {

	b, _ := aes.NewCipher([]byte(passphrase))
	blockSize := b.BlockSize()
	counter := make([]byte, 8)
	var ctxt []byte

	for i := 0; i < len(ptxt); i += blockSize {

		//append nonce and counter
		src := append(nonce, counter...)

		dst := make([]byte, blockSize)
		b.Encrypt(dst, src)
		if (i + blockSize) < len(ptxt) {
			ctxt = append(ctxt, xor(dst, ptxt[i:i+blockSize])...)
		} else {
			ctxt = append(ctxt, xor(dst[0:len(ptxt[i:])], ptxt[i:])...)
		}

		//increment counter
		temp := binary.LittleEndian.Uint64(counter)
		temp++
		binary.LittleEndian.PutUint64(counter, uint64(temp))
	}

	return ctxt
}

var aesCtrDecrypt = aesCtrEncrypt

func getctrEncryptionOracle() (
	ctrEncryptionOracle func([]byte) []byte,
) {
	encryptionKey := generateRandomBytes(BLOCKSIZE)
	nonce := make([]byte, 8)

	ctrEncryptionOracle = func(in []byte) []byte {
		return aesCtrEncrypt(in, encryptionKey, nonce)
	}
	return
}

func breakFixedNonceCTR(ctxts [][]byte, freqMap map[rune]float64) []byte {

	var xorKey []byte
	var longestLen = 0
	for _, ctxt := range ctxts {
		if len(ctxt) > longestLen {
			longestLen = len(ctxt)
		}
	}
	bs := 1
	for i := 0; i < longestLen; i += bs {
		var column []byte
		for _, ctxt := range ctxts {
			if (i + bs) < len(ctxt) {
				column = append(column, ctxt[i:i+bs]...)
			}
		}
		xorKey = append(xorKey, findRepeatingXorKey(column, freqMap, bs)...)
	}
	return xorKey
}
