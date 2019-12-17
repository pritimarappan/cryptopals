package cryptopals

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/bits"
	"net/http"
	"os"
	"sort"
	"unicode/utf8"
)

func hexToBytes(hexStr string) ([]byte, error) {

	data, err := hex.DecodeString(hexStr)

	if err != nil {
		fmt.Println(err)
	}
	log.Printf("%s", data)
	return data, nil
}

func bytesToB64(inputData []byte) (string, error) {
	str := base64.StdEncoding.EncodeToString(inputData)
	fmt.Println(str)
	return str, nil
}

func xor(ip1 []byte, ip2 []byte) []byte {
	if len(ip1) != len(ip2) {
		panic("xor: unequal length for input")
	}
	result := make([]byte, len(ip1))
	for i := range ip1 {
		result[i] = ip1[i] ^ ip2[i]
	}
	return result
}

func downloadFile(filepath string, url string) error {

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

func buildFrequencyMap(text string) map[rune]float64 {

	freqMap := make(map[rune]float64)

	for _, char := range text {
		freqMap[char]++
	}
	total := utf8.RuneCountInString(text)
	//normalise
	for key := range freqMap {
		freqMap[key] = freqMap[key] / float64(total)
	}

	return freqMap
}

func xorWithSingleByteKey(cipher []byte, key byte, freqMap map[rune]float64) ([]byte, float64) {

	plaintext := make([]byte, len(cipher))

	var score float64
	for i, c := range cipher {
		plaintext[i] = c ^ key
		score = score + freqMap[rune(plaintext[i])]
	}
	score = score / float64(utf8.RuneCountInString(string(plaintext)))
	return plaintext, score
}

func breakSingleByteXor(ciphertext []byte, freqMap map[rune]float64) (lastScore float64, plaintext string, finalKey byte) {

	for key := byte(0); key < 255; key++ {

		ptxt, score := xorWithSingleByteKey(ciphertext, key, freqMap)

		if score > lastScore {
			plaintext = string(ptxt)
			lastScore = score
			finalKey = key
		}
	}

	return
}

func repeatingXOR(input, key []byte) []byte {

	res := make([]byte, len(input))
	for i := range input {
		res[i] = input[i] ^ (key[i%len(key)])
	}
	return res
}

func computeHammingDistance(input1, input2 []byte) int {
	var hammingDistance int

	if len(input1) != len(input2) {
		panic("wrong input")
	}

	for i := range input1 {
		if input1[i] != input2[i] {
			hammingDistance += bits.OnesCount8(input1[i] ^ input2[i])
		}
	}
	return hammingDistance
}

func findRepeatingXorKeySize(input []byte) (map[float64]int, []float64) {
	var temp float64
	scoreList := make(map[float64]int)
	bs := 4

	for keyLen := 2; keyLen < 40; keyLen++ {
		dist := computeHammingDistance(input[:keyLen*bs], input[keyLen*bs:keyLen*bs*2])
		temp = float64(dist) / float64(keyLen)
		scoreList[temp] = keyLen
	}

	keys := make([]float64, 0, len(scoreList))
	for k := range scoreList {
		keys = append(keys, k)
	}
	sort.Float64s(keys)

	return scoreList, keys
}

func findRepeatingXorKey(input []byte, freqMap map[rune]float64, keySize int) []byte {

	fmt.Println("key size: ", keySize)
	var res = make([]byte, keySize)
	var block = make([]byte, (len(input)+keySize-1)/keySize)

	for i := 0; i < keySize; i++ {
		for j := range block {
			if j*keySize+i < len(input) {
				block[j] = input[j*keySize+i]
			}
		}

		_, _, b := breakSingleByteXor(block, freqMap)
		res[i] = b
	}

	return res
}

func aesEcbDecrypt(ciphertext []byte, passphrase string) []byte {
	cipher, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		panic(err.Error())
	}
	if len(ciphertext)%cipher.BlockSize() != 0 {
		panic("input requires padding")
	}
	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i += cipher.BlockSize() {
		cipher.Decrypt(plaintext[i:], ciphertext[i:])
	}
	return plaintext
}

func aesEcbEncrypt(pt []byte, passphrase string) []byte {
	cipher, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		panic(err.Error())
	}
	if len(pt)%cipher.BlockSize() != 0 {
		panic("input requires padding")
	}
	ct := make([]byte, len(pt))

	for i := 0; i < len(pt); i += cipher.BlockSize() {
		cipher.Encrypt(ct[i:], pt[i:])
	}
	return ct
}

func detectECB(in []byte, blockSize int) bool {
	if len(in)%blockSize != 0 {
		panic("input requires padding")
	}

	parsedBlocks := make(map[string]int)

	for i := 0; i < len(in); i += blockSize {
		parsedBlocks[string(in[i:i+blockSize])]++
		val := parsedBlocks[string(in[i:i+blockSize])]
		if val > 1 {
			return true
		}
	}
	return false
}
