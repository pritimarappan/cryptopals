package cryptopals

import (
	"bytes"
	"fmt"
	"testing"
)

func Test9(t *testing.T) {
	in := []byte("YELLOW SUBMARINE")
	out := pkcs7Padding(in, 20)
	fmt.Println(bytes.Equal(out, []byte("YELLOW SUBMARINE\x04\x04\x04\x04")))
}

func Test10(t *testing.T) {
	key := "YELLOW SUBMARINE"
	iv := make([]byte, 16) //golang initializes with zero; "0000000000000000" is not all ASCII zero.
	ptxt := []byte("123456 123456789")
	ctxt := aesCbcEncrypt(ptxt, []byte(key), iv)
	ptxt2 := aesCbcDecrypt(ctxt, []byte(key), iv)
	fmt.Println(string(ptxt2))

	b64Ciphertext := string(readFile("10.txt", t))
	ctxt3 := decodeBase64(b64Ciphertext)
	ptxt3 := aesCbcDecrypt(ctxt3, []byte(key), iv)
	fmt.Println(string(ptxt3))
}

func Test11(t *testing.T) {
	oracle := encryptionOracle()
	payload := bytes.Repeat([]byte{42}, 16*3)
	cbc, ecb := 0, 0

	for i := 0; i < 500; i++ {
		out := oracle(payload)
		if detectECB(out, 16) {
			ecb++
		} else {
			cbc++
		}
	}
	fmt.Println(ecb, cbc)
}

func Test12(t *testing.T) {
	suffix := decodeBase64(
		`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`)

	oracle := simpleECBEncryption(suffix)
	blockSize := detectBlockSize(oracle)
	ecbDetected := false

	for i := 1; i < 32; i++ {

		out := oracle(bytes.Repeat([]byte{'A'}, i*blockSize))
		if detectECB(out, blockSize) {
			ecbDetected = true
			break
		}
	}
	if !ecbDetected {
		panic("ecb not detected")
	}

	dict := buildDictToBreakEcb(oracle, blockSize)

	ptxt := make([]byte, len(suffix))
	msg := bytes.Repeat([]byte{'A'}, blockSize)
	for i := 0; i < len(suffix); i++ {
		msg[blockSize-1] = suffix[i]
		out := string(oracle(msg)[:blockSize-1])
		ptxt[i] = dict[out]
	}
	fmt.Println(string(ptxt))
}

func Test13(t *testing.T) {
	getEncryptedProfile, _ := oracles()
	encryptedProfile := getEncryptedProfile([]byte("fo"))

	block1 := encryptedProfile[0:16] //Uid=81&email=fo&

}
