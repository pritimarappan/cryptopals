package cryptopals

import (
	"crypto/aes"
	"crypto/rand"
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

func aesCbcEncrypt(plaintext []byte, passphrase string, iv []byte) []byte {

	b, _ := aes.NewCipher([]byte(passphrase))
	blockSize := b.BlockSize()
	if len(plaintext)%blockSize != 0 {
		panic("padding required for plain text")
	}
	ciphertext := make([]byte, len(plaintext))

	for i := 0; i < len(plaintext); i += blockSize {
		copy(ciphertext[i:i+blockSize], aesEcbEncrypt(xor(iv, plaintext[i:i+blockSize]), passphrase))
		iv = ciphertext[i : i+blockSize]
	}
	return ciphertext
}

func aesCbcDecrypt(ciphertext []byte, passphrase string, iv []byte) []byte {

	b, _ := aes.NewCipher([]byte(passphrase))
	blockSize := b.BlockSize()
	if len(ciphertext)%blockSize != 0 {
		panic("padding required for ciphertext")
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
