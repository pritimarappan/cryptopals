package cryptopals

import (
	"fmt"
	"testing"
)

func Test17(t *testing.T) {
	encryptionOracle, paddingOracle := cbcPaddingOracles()
	ciphertext, _ := encryptionOracle()
	//ct := ciphertext[len(ciphertext)-16-16:]
	//fmt.Println(paddingOracle(ct[16:], ct[:16]))
	ct := make([]byte, 32)
	for i := 0; i < 256; i++ {
		copy(ct, ciphertext[len(ciphertext)-32:]) //last 2 bytes
		ct[len(ct)-1] ^= byte(1) ^ byte(i)
		if paddingOracle(ct[16:], ct[0:16]) {
			fmt.Println(byte(i))
		}
	}
}
