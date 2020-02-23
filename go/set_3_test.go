package cryptopals

import (
	"bufio"
	"fmt"
	"os"
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

func Test19(t *testing.T) {
	ptxts := readFilePerLine("19.txt", t)

	b := readFile("alice.txt", t)
	freqMap := buildFrequencyMap(string(b))

	ctrOracle := getctrEncryptionOracle()
	var ctxts [][]byte
	for _, ptxt := range ptxts {
		ctxts = append(ctxts, ctrOracle(ptxt))
	}
	xorKey := breakFixedNonceCTR(ctxts, freqMap)

	for i := 0; i < len(ctxts); i++ {
		fmt.Println(string(xor(ctxts[i], xorKey[0:len(ctxts[i])])))
	}
}

func readFilePerLine(filePath string, t *testing.T) [][]byte {

	file, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}

	var lines [][]byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, decodeBase64(scanner.Text()))
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	return lines
}

func Test20(t *testing.T) {
	ptxts := readFilePerLine("20.txt", t)

	b := readFile("alice.txt", t)
	freqMap := buildFrequencyMap(string(b))

	ctrOracle := getctrEncryptionOracle()
	var ctxts [][]byte
	for _, ptxt := range ptxts {
		ctxts = append(ctxts, ctrOracle(ptxt))
	}
	xorKey := breakFixedNonceCTR(ctxts, freqMap)

	for i := 0; i < len(ctxts); i++ {
		fmt.Println(string(xor(ctxts[i], xorKey[0:len(ctxts[i])])))
	}
}
