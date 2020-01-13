package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	mathrand "math/rand"
	"net/url"
	"strconv"
)

func pkcs7Padding(in []byte, paddingLength int) []byte {
	if paddingLength >= 256 {
		panic("Invalid padding length for PKCS7")
	}

	pad := paddingLength - (len(in) % paddingLength)

	buffer := make([]byte, (pad))
	for i := 0; i < (pad); i++ {
		buffer[i] = byte(pad)
	}
	return (append(in, buffer...))
	//return (append(in, bytes.Repeat([]byte{byte(pad)}, pad)...))
}

func aesCbcEncrypt(plaintext []byte, passphrase []byte, iv []byte) []byte {

	b, _ := aes.NewCipher([]byte(passphrase))
	blockSize := b.BlockSize()
	if len(plaintext)%blockSize != 0 {
		panic("padding required for plain text in aesCbcEncrypt")
	}
	ciphertext := make([]byte, len(plaintext))

	for i := 0; i < len(plaintext); i += blockSize {
		copy(ciphertext[i:i+blockSize], aesEcbEncrypt(xor(iv, plaintext[i:i+blockSize]), passphrase))
		iv = ciphertext[i : i+blockSize]
	}
	return ciphertext
}

func aesCbcDecrypt(ciphertext []byte, passphrase []byte, iv []byte) []byte {

	b, _ := aes.NewCipher(passphrase)
	blockSize := b.BlockSize()
	if len(ciphertext)%blockSize != 0 {
		panic("padding required for ciphertext in aesCbcDecrypt")
	}

	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i += blockSize {
		copy(plaintext[i:i+blockSize], xor(iv, aesEcbDecrypt(ciphertext[i:i+blockSize], passphrase)))
		iv = ciphertext[i : i+blockSize]
	}
	return plaintext
}

//Write a function to generate a random AES key; that's just 16 random bytes.
func generateRandomBytes(numOfBytes int) []byte {

	b := make([]byte, numOfBytes)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func encryptionOracle() func([]byte) []byte {
	encryptionKey := generateRandomBytes(16)

	return func(ptxt []byte) []byte {
		prefix := make([]byte, 5+mathrand.Intn(5))
		_, err := rand.Read(prefix)
		if err != nil {
			panic(err)
		}
		suffix := make([]byte, 5+mathrand.Intn(5))
		_, err = rand.Read(suffix)
		if err != nil {
			panic(err)
		}
		msg := append(append(prefix, ptxt...), suffix...)
		msg = pkcs7Padding(msg, 16)

		oracle := mathrand.Intn(2)

		if oracle == 0 {
			return aesEcbEncrypt(msg, encryptionKey)
		}
		return aesCbcEncrypt(msg, encryptionKey, generateRandomBytes(16))

	}
}

func simpleECBEncryption(suffix []byte) func([]byte) []byte {
	encryptionKey := generateRandomBytes(16)

	return func(in []byte) []byte {

		msg := append(in, suffix...)
		msg = pkcs7Padding(msg, 16)

		return aesEcbEncrypt(msg, encryptionKey)

	}
}

func detectBlockSize(oracle func([]byte) []byte) int {
	blockSize := 0
	temp := len(oracle(bytes.Repeat([]byte{42}, 1)))
	for i := 2; i < 32; i++ {
		out := oracle(bytes.Repeat([]byte{42}, i))

		if len(out)-temp > 0 {
			blockSize = len(out) - temp
			break
		} else {
			temp = len(out)
		}
	}
	if blockSize == 0 {
		panic("block size not found")
	}
	return blockSize
}

func buildDictToBreakEcb(oracle func([]byte) []byte, blockSize int) map[string]byte {
	dict := make(map[string]byte)

	msg := bytes.Repeat([]byte{'A'}, blockSize)
	for b := 0; b < 256; b++ {
		msg[blockSize-1] = byte(b)
		out := string(oracle(msg)[:blockSize-1])
		dict[out] = byte(b)
	}

	return dict
}

func profileFor(in string) string {
	v := url.Values{}
	v.Set("email", in)
	v.Add("uid", strconv.Itoa(mathrand.Intn(100)))
	v.Add("role", "user")
	return v.Encode()
}

func oracles() (
	encryptionOracle func([]byte) []byte,
	decryptionOracle func([]byte) []byte,
) {
	encryptionKey := generateRandomBytes(16)

	encryptionOracle = func(in []byte) []byte {
		msg := pkcs7Padding(in, 16)
		return aesEcbEncrypt(msg, encryptionKey)
	}

	decryptionOracle = func(in []byte) []byte {
		return aesEcbDecrypt(in, encryptionKey)
	}
	return
}

func isAdmin(profile string) bool {

	values, err := url.ParseQuery(profile)
	if err != nil {
		panic("error in decoding profile")
	}
	if values.Get("role") == "admin" {
		return true
	}
	return false
}
