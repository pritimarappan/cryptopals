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
	ptxt := []byte("123456 123456789")
	ctxt := aesCbcEncrypt(ptxt, key)
	ptxt2 := aesCbcDecrypt(ctxt, key)
	fmt.Print(string(ptxt2))
}
