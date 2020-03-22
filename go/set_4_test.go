package cryptopals

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func Test25(t *testing.T) {
	passphrase := "YELLOW SUBMARINE"
	bInB64 := readFile("25.txt", t)
	b := decodeBase64(string(bInB64))
	ptxt := aesEcbDecrypt(b, []byte(passphrase))
	ctrOracle, ctrEditOracle := getctrOracles()
	ctxt := ctrOracle(ptxt)
	var recoveredPtxt []byte
	newText := bytes.Repeat([]byte{42}, 16)
	for i := 0; i <= len(ctxt)-16; i += 16 {
		ctxt2 := ctrEditOracle(ctxt, i, newText)
		recoveredPtxt = append(recoveredPtxt, xor(xor(ctxt[i:i+16], ctxt2[i:i+16]), newText)...)
	}
	fmt.Println(string(recoveredPtxt))
}

func Test26(t *testing.T) {
	generateCookie, isAdmin := getCtrOracles()

	if isAdmin(generateCookie([]byte(";admin=true;"))) {
		fmt.Println("this shouldn't work")
	}
	fmt.Println("final attack  ", isAdmin(makeCtrAdminCookie(generateCookie)))

}

func Test27(t *testing.T) {
	encryptMsg, decryptMsg := getCbcOraclesWithKeyAsIv()
	ptxt := bytes.Repeat([]byte("A"), BLOCKSIZE*3)
	ctxt := encryptMsg(ptxt)
	var modifiedCtxt []byte
	modifiedCtxt = append(append(append(modifiedCtxt, ctxt[0:BLOCKSIZE]...), bytes.Repeat([]byte{0}, BLOCKSIZE)...), ctxt[0:BLOCKSIZE]...)
	err := decryptMsg(modifiedCtxt)
	ptxt1 := []byte(strings.TrimPrefix(err, "invalid message: "))
	key := xor(ptxt1[0:BLOCKSIZE], ptxt1[BLOCKSIZE*2:])
	temp, _ := pkcs7UnPadding(aesCbcDecrypt(ctxt, key, key))
	if bytes.Equal(temp, ptxt) {
		fmt.Println("success")
	} else {
		fmt.Println("key recovered incorrectly")
	}
}

func Test28(t *testing.T) {
	key := generateRandomBytes(16)
	msg := bytes.Repeat([]byte{42}, 20)
	mac := getSecretPrefixSha1(key, msg)
	fmt.Println("Mac verification without tampering anything : ", verifySecretPrefixSha1(key, msg, mac))
	msg[19] = 'a'
	fmt.Println("Mac verification after tampering msg : ", verifySecretPrefixSha1(key, msg, mac))
	msg[19] = 42
	mac[len(mac)-1] = 'a'
	fmt.Println("Mac verification after tampering mac : ", verifySecretPrefixSha1(key, msg, mac))
}

func Test29(t *testing.T) {

	msg := bytes.Repeat([]byte{42}, 60)

	h1 := newSHA1()
	//h1.Write(key)
	h1.Write(msg)
	h1.checkSum()

	h2 := newSHA1()
	//h2.Write(key)
	h2.Write(msg)
	h2.Write(computeMDPadding(len(msg)))

	if h1.h != h2.h {
		fmt.Println("hash state don't match")
	}
	attackSha1()
}
