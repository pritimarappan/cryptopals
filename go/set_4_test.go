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
