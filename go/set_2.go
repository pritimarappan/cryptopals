package cryptopals

import "crypto/aes"

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

func aesCbcEncrypt(plaintext []byte, passphrase string) []byte {

	b, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	blockSize := b.BlockSize()
	if len(plaintext)%blockSize != 0 {
		panic("padding required for plain text")
	}
	iv := []byte("0000000000000000")

	ciphertext := make([]byte, len(plaintext))

	for i := 0; i < len(plaintext); i += blockSize {
		copy(ciphertext[i:i+blockSize], aesEcb(xor(iv, plaintext[i:i+blockSize]), passphrase))
		iv = ciphertext[i : i+blockSize]
	}
	return ciphertext
}

func aesCbcDecrypt(ciphertext []byte, passphrase string) []byte {

	b, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	blockSize := b.BlockSize()
	if len(ciphertext)%blockSize != 0 {
		panic("padding required for ciphertext")
	}
	iv := []byte("0000000000000000")

	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i += blockSize {
		copy(plaintext[i:i+blockSize], xor(iv, aesEcb(ciphertext[i:i+blockSize], passphrase)))
		iv = ciphertext[i : i+blockSize]
	}
	return plaintext
}
