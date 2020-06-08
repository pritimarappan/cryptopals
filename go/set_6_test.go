package cryptopals

import (
	cryptosha1 "crypto/sha1"
	"fmt"
	"math/big"
	"testing"
)

func Test41(t *testing.T) {
	rsaUnpaddedMsgRecovery()
}

func Test42(t *testing.T) {
	keySize := 1024 / 8
	target := make([]byte, keySize)
	for i := range target {
		target[i] = 0xff
	}
	target = target[:0]
	target = append(target, 0x00)
	target = append(target, 0x01)
	target = append(target, 0x00)
	target = append(target, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14)
	h := cryptosha1.Sum([]byte{42})
	target = append(target, h[:]...)
	target = target[:cap(target)]
	t1 := new(big.Int).SetBytes(target)
	root := cubeRoot(t1)
	// log.Printf("%x", new(big.Int).Exp(root, big3, nil))
	sig := root.Bytes()

	verify := bb06Oracle()

	fmt.Println(verify([]byte{42}, sig))
}
