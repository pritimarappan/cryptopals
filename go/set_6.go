package cryptopals

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func rsaUnpaddedMsgRecovery() {

	r := new(rsa)
	r.generateRsaKeys()
	m := big.NewInt(42)
	C := r.rsaEncrypt(m)

	s, err := rand.Int(rand.Reader, r.pub.N)
	if err != nil {
		panic(err)
	}
	S := new(big.Int).Exp(s, r.pub.E, r.pub.N)
	Chash := new(big.Int)
	Chash.Mul(C, S).Mod(Chash, r.pub.N)

	p1 := r.rsaDecrypt(Chash)

	pRecovered := new(big.Int).Mul(p1, new(big.Int).ModInverse(s, r.pub.N))
	ptxt := pRecovered.Mod(pRecovered, r.pub.N)

	if ptxt.Cmp(m) != 0 {
		fmt.Println("msg not recovered")
	} else {
		fmt.Println("success")
	}

}

func bb06Oracle() (verifySign func(msg []byte, sign []byte) bool) {

	r := new(rsa)
	r.generateRsaKeys()

	verifySign = func(msg []byte, sign []byte) bool {
		signBytes := new(big.Int).SetBytes(sign)
		s := r.rsaEncrypt(signBytes)
		//ans1Sha1 := []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}
		fmt.Printf("[% x]", s)
		return true
	}
	return
}
