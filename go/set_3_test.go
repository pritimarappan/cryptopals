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
