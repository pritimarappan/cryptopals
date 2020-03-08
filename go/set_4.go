package cryptopals

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

func getctrOracles() (
	ctrEncryptionOracle func([]byte) []byte,
	ctrEditnOracle func([]byte, int, []byte) []byte,
) {
	encryptionKey := generateRandomBytes(BLOCKSIZE)
	nonce := make([]byte, 8)

	ctrEncryptionOracle = func(in []byte) []byte {
		return aesCtrEncrypt(in, encryptionKey, nonce)
	}
	ctrEditnOracle = func(ciphertext []byte, offset int, newText []byte) []byte {
		ptxt := aesCtrDecrypt(ciphertext, encryptionKey, nonce)
		ptxt = append(append(ptxt[0:offset], newText...), ptxt[offset+len(newText):]...)
		return aesCtrEncrypt(ptxt, encryptionKey, nonce)
	}
	return
}

func getCtrOracles() (
	generateCookie func([]byte) []byte,
	isAdmin func([]byte) bool,
) {
	encryptionKey := generateRandomBytes(BLOCKSIZE)
	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"
	nonce := generateRandomBytes(BLOCKSIZE)
	generateCookie = func(in []byte) []byte {
		encodedIn := bytes.Replace(in, []byte("="), []byte("%3D"), -1)
		encodedIn = bytes.Replace(encodedIn, []byte(";"), []byte("%3B"), -1)
		msg := append(append([]byte(prefix), encodedIn...), []byte(suffix)...)
		//msg = pkcs7Padding(msg, BLOCKSIZE)
		return aesCtrEncrypt(msg, encryptionKey, nonce)
		//return aesCbcEncrypt(msg, encryptionKey, iv)
	}

	isAdmin = func(in []byte) bool {
		decryptedProfileArr := aesCtrDecrypt(in, encryptionKey, nonce)
		decryptedProfile := string(decryptedProfileArr)
		fmt.Println(decryptedProfile)
		return strings.Contains(decryptedProfile, ";admin=true;")
	}
	return
}

func makeCtrAdminCookie(generateCookie func([]byte) []byte) []byte {
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

func getCbcOraclesWithKeyAsIv() (
	encryptMsg func([]byte) []byte,
	decryptMsg func([]byte) string,
) {
	encryptionKey := generateRandomBytes(BLOCKSIZE)
	iv := encryptionKey
	encryptMsg = func(in []byte) []byte {
		msg := pkcs7Padding(in, BLOCKSIZE)
		return aesCbcEncrypt(msg, encryptionKey, iv)
	}

	decryptMsg = func(ctxt []byte) string {
		decryptedProfileArr, _ := pkcs7UnPadding(aesCbcDecrypt(ctxt, encryptionKey, iv))
		decryptedProfile := string(decryptedProfileArr)

		if !regexp.MustCompile(`^[ -~]+$`).Match(decryptedProfileArr) { //regex doesn't match for ascii printable chars
			return ("invalid message: " + decryptedProfile)
		}
		return ""
	}
	return
}
