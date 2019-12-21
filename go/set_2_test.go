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
	ctxt3 := decodeBase64(b64Ciphertext, t)
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
