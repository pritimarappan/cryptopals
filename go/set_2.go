package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"
	mathrand "math/rand"
	"net/url"
	"strconv"
	"strings"
)

//BLOCKSIZE is the encryption blocksize
const BLOCKSIZE = 16

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
	encryptionKey := generateRandomBytes(BLOCKSIZE)

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
		return aesCbcEncrypt(msg, encryptionKey, generateRandomBytes(BLOCKSIZE))

	}
}

func simpleECBEncryption(suffix []byte) func([]byte) []byte {
	encryptionKey := generateRandomBytes(BLOCKSIZE)

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
	v.Add("Uid", strconv.Itoa(mathrand.Intn(100)))
	v.Add("role", "user")
	return v.Encode()
}

func oracles() (
	getEncryptedProfile func([]byte) []byte,
	isAdmin func([]byte) bool,
) {
	encryptionKey := generateRandomBytes(BLOCKSIZE)

	getEncryptedProfile = func(in []byte) []byte {
		msg := []byte(profileFor(string(in)))
		msg = pkcs7Padding([]byte(msg), 16)
		return aesEcbEncrypt(msg, encryptionKey)
	}

	isAdmin = func(in []byte) bool {
		decryptedProfile := aesEcbDecrypt(in, encryptionKey)
		values, err := url.ParseQuery(string(decryptedProfile))
		if err != nil {
			panic("error in decoding profile")
		}
		if values.Get("role") == "admin" {
			return true
		}
		return false
	}
	return
}

func harderECBEncryption(suffix []byte) func([]byte) []byte {
	encryptionKey := generateRandomBytes(BLOCKSIZE)

	randomPrefix := generateRandomBytes(mathrand.Intn(10))
	fmt.Println(len(randomPrefix))
	return func(in []byte) []byte {

		msg := append(randomPrefix, append(in, suffix...)...)
		msg = pkcs7Padding(msg, 16)

		return aesEcbEncrypt(msg, encryptionKey)

	}
}

func findRepeatingBlock(in []byte, blockSize int) int {

	for i := 0; i+2 <= len(in)/blockSize; i++ {
		if bytes.Equal(in[blockSize*i:blockSize*(i+1)], in[blockSize*(i+1):blockSize*(i+2)]) {
			return i
		}
	}
	return -1
}

func buildDictToBreakEcbWithPrefix(oracle func([]byte) []byte, blockSize int, prefixLen int) map[string]byte {
	dict := make(map[string]byte)

	msg := bytes.Repeat([]byte{'A'}, blockSize-prefixLen)
	for b := 0; b < 256; b++ {
		msg[blockSize-prefixLen-1] = byte(b)
		out := string(oracle(msg)[:blockSize-1])
		dict[out] = byte(b)
	}
	return dict
}

func pkcs7UnPadding(in []byte) ([]byte, error) {

	if len(in) == 0 {
		return in, nil
	}
	lastByte := in[len(in)-1]
	if int(lastByte) < 1 || int(lastByte) > len(in) {
		return nil, nil
	}
	for i := 0; i < int(lastByte); i++ {
		if int(in[len(in)-1-i]) != int(lastByte) {
			return nil, errors.New("invalid padding")
		}
	}
	return in[:len(in)-int(lastByte)], nil
}

func getCbcOracles() (
	generateCookie func([]byte) []byte,
	isAdmin func([]byte) bool,
) {
	encryptionKey := generateRandomBytes(BLOCKSIZE)
	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"
	iv := generateRandomBytes(BLOCKSIZE)
	generateCookie = func(in []byte) []byte {
		encodedIn := bytes.Replace(in, []byte("="), []byte("%3D"), -1)
		encodedIn = bytes.Replace(encodedIn, []byte(";"), []byte("%3B"), -1)
		msg := append(append([]byte(prefix), encodedIn...), []byte(suffix)...)
		msg = pkcs7Padding(msg, BLOCKSIZE)

		return aesCbcEncrypt(msg, encryptionKey, iv)
	}

	isAdmin = func(in []byte) bool {
		decryptedProfileArr, err := pkcs7UnPadding(aesCbcDecrypt(in, encryptionKey, iv))
		if err != nil {
			fmt.Println("Unpadding errors")
		}
		decryptedProfile := string(decryptedProfileArr)
		fmt.Println(decryptedProfile)
		return strings.Contains(decryptedProfile, ";admin=true;")
	}
	return
}

func xorString(a, b string) string {
	return string(xor([]byte(a), []byte(b)))
}

func makeCBCAdminCookie(generateCookie func([]byte) []byte) []byte {
	//comment1=cooking%20MCs;userdata=AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA
	prefix := "comment1=cooking%20MCs;userdata="
	target := "AA;admin=true;AA"
	msg := bytes.Repeat([]byte{'A'}, 16*2)
	out := generateCookie(msg)
	block1 := out[:len(prefix)]                 //comment1=cooking%20MCs;userdata=
	block2 := out[len(prefix) : len(prefix)+16] //AAAAAAAAAAAAAAAA
	block3 := out[len(prefix)+16:]              //";comment2=%20like%20a%20pound%20of%20bacon"
	block2 = xor(block2, xor(bytes.Repeat([]byte{'A'}, 16), []byte(target)))
	return append(append(block1, block2...), block3...)
}
