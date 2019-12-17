package cryptopals

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
)

func Test1(t *testing.T) {
	dataInBytes, err := hexToBytes("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")

	if err != nil {
		t.Fatal(err)
	}
	dataInB64, err := bytesToB64(dataInBytes)
	if dataInB64 != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.Fatal("Output is wrong")
	}
}

func Test2(t *testing.T) {
	ip1InBytes, err := hexToBytes("1c0111001f010100061a024b53535009181c")
	ip2InBytes, err := hexToBytes("686974207468652062756c6c277320657965")

	if err != nil {
		t.Fatal(err)
	}

	res := xor(ip1InBytes, ip2InBytes)
	resStr := hex.EncodeToString(res)

	if resStr != "746865206b696420646f6e277420706c6179" {
		t.Fatal("Output is wrong")
	}
}

func Test3(t *testing.T) {
	//download file
	//url := "https://www.gutenberg.org/files/11/11-0.txt"
	filePath := "alice.txt"

	//read file
	b := readFile(filePath, t) // just pass the file name

	//build freq map
	freqMap := buildFrequencyMap(string(b))

	//change hex to byte array
	b = decodeHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", t)

	//score all keys
	score, result, key := breakSingleByteXor(b, freqMap)

	//print result
	fmt.Println("result", result)
	fmt.Println("score", score)
	fmt.Println("key", key)

	//delete file
	// err = os.Remove(filePath)
	// if err != nil {
	// 	t.Fatal(err)
	// }
}

func Test4(t *testing.T) {

	//read file
	b := readFile("alice.txt", t)
	//build freq map
	freqMap := buildFrequencyMap(string(b))

	//read file
	text := readFile("4.txt", t)

	var bestScore float64
	var plainText string

	for _, line := range strings.Split(string(text), "\n") {

		lastScore, str, key := breakSingleByteXor(decodeHex(line, t), freqMap)

		if bestScore < lastScore {
			bestScore = lastScore
			plainText = str
		}
		t.Log("key", key)
	}
	fmt.Println("result", plainText)

}

func decodeHex(input string, t *testing.T) []byte {
	inputInBytes, err := hex.DecodeString(input)
	if err != nil {
		t.Fatal("failed to decode hex:", input)
	}
	return inputInBytes
}

func readFile(filePath string, t *testing.T) []byte {
	b, err := ioutil.ReadFile(filePath) // just pass the file name
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func Test5(t *testing.T) {
	input := []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)

	res := repeatingXOR(input, []byte("ICE"))

	if bytes.Equal(res, decodeHex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", t)) {
		fmt.Println("Result is right")
	}
	if !bytes.Equal(res, decodeHex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", t)) {
		fmt.Println("Result is wrong")
	}
}

func Test6(t *testing.T) {

	fmt.Println("hamming dist: ", computeHammingDistance([]byte("this is a test"), []byte("wokka wokka!!!")))

	//read file
	b := readFile("alice.txt", t)

	//build freq map
	freqMap := buildFrequencyMap(string(b))
	b = decodeBase64(string(readFile("6.txt", t)), t)
	scoreList, keys := findRepeatingXorKeySize(b)

	key := findRepeatingXorKey(b, freqMap, scoreList[keys[0]])
	text := repeatingXOR(b, key)
	fmt.Println("key", string(text))
}

func Test7(t *testing.T) {
	passphrase := "YELLOW SUBMARINE"
	bInB64 := readFile("7.txt", t)
	b := decodeBase64(string(bInB64), t)
	ptxt := aesEcbDecrypt(b, passphrase)
	fmt.Println(string(ptxt))
}

func Test8(t *testing.T) {
	lines := string(readFile("8.txt", t))
	for i, hexString := range strings.Split(lines, "\n") {
		if detectECB(decodeHex(hexString, t), 16) {
			fmt.Println("line encrypted with ECB", i+1)
		}
	}
}

func decodeBase64(s string, t *testing.T) []byte {
	t.Helper()
	v, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal("failed to decode base64:", s)
	}
	return v
}
