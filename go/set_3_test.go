package cryptopals

import (
	"fmt"
	"testing"
)

func Test17(t *testing.T) {
	encryptionOracle, paddingOracle := cbcPaddingOracles()
	ciphertext, iv := encryptionOracle()
	ciphertext = append(iv, ciphertext...)
	var ptxt []byte
	for i := len(ciphertext); i >= 32; i -= 16 {
		pt := attackCbcPaddingOracle(ciphertext[i-32:i], paddingOracle)
		ptxt = append(pt, ptxt...)
	}
	fmt.Println(string(ptxt))
}

func Test18(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	nonce := make([]byte, 8)
	ctxt := decodeBase64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	fmt.Println(string(aesCtrDecrypt(ctxt, key, nonce)))
}
