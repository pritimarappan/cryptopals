package cryptopals

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
	mathrand "math/rand"
	"time"
)

func cbcPaddingOracles() (
	encryptionOracle func() (ciphertext []byte, iv []byte),
	paddingOracle func([]byte, []byte) bool) {
	list := [10]string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"}

	encryptionKey := generateRandomBytes(16)

	encryptionOracle = func() (ciphertext []byte, iv []byte) {
		ptxt := decodeBase64(list[mathrand.Intn(len(list))])
		iv = generateRandomBytes(16)
		ciphertext = aesCbcEncrypt(pkcs7Padding([]byte(ptxt), 16), encryptionKey, iv)
		return
	}
	paddingOracle = func(ciphertext []byte, iv []byte) bool {

		ptxt, _ := pkcs7UnPadding(aesCbcDecrypt(ciphertext, encryptionKey, iv))
		if ptxt != nil {
			return true
		}
		return false
	}
	return
}

func attackCbcPaddingOracle(ctxt []byte, paddingOracle func([]byte, []byte) bool) []byte {

	getPtxtBytes := func(foundBytes []byte) []byte {
		ct := make([]byte, 32)
		ptxt := append([]byte{0}, foundBytes...)

		for ptxtGuess := 0; ptxtGuess < 256; ptxtGuess++ {

			copy(ct, ctxt)
			for i := 1; i <= len(foundBytes); i++ {
				ct[len(ct)-16-i] ^= byte(len(foundBytes)+1) ^ byte(foundBytes[len(foundBytes)-i])
			}

			ct[len(ct)-16-(len(foundBytes)+1)] ^= byte(len(foundBytes)+1) ^ byte(ptxtGuess)
			if paddingOracle(ct[16:], ct[0:16]) && (byte(ptxtGuess)^byte(1) != byte(0)) {
				ptxt[0] = byte(ptxtGuess)
			}
		}
		return ptxt
	}
	var ptxt []byte
	for i := 0; i < 16; i++ {
		ptxt = getPtxtBytes(ptxt)
	}

	return ptxt
}

func aesCtrEncrypt(ptxt []byte, passphrase []byte, nonce []byte) []byte {

	b, _ := aes.NewCipher([]byte(passphrase))
	blockSize := b.BlockSize()
	counter := make([]byte, 8)
	var ctxt []byte

	for i := 0; i < len(ptxt); i += blockSize {

		//append nonce and counter
		src := append(nonce, counter...)

		dst := make([]byte, blockSize)
		b.Encrypt(dst, src)
		if (i + blockSize) < len(ptxt) {
			ctxt = append(ctxt, xor(dst, ptxt[i:i+blockSize])...)
		} else {
			ctxt = append(ctxt, xor(dst[0:len(ptxt[i:])], ptxt[i:])...)
		}

		//increment counter
		temp := binary.LittleEndian.Uint64(counter)
		temp++
		binary.LittleEndian.PutUint64(counter, uint64(temp))
	}

	return ctxt
}

var aesCtrDecrypt = aesCtrEncrypt

func getctrEncryptionOracle() (
	ctrEncryptionOracle func([]byte) []byte,
) {
	encryptionKey := generateRandomBytes(BLOCKSIZE)
	nonce := make([]byte, 8)

	ctrEncryptionOracle = func(in []byte) []byte {
		return aesCtrEncrypt(in, encryptionKey, nonce)
	}
	return
}

func breakFixedNonceCTR(ctxts [][]byte, freqMap map[rune]float64) []byte {

	var xorKey []byte
	var longestLen = 0
	for _, ctxt := range ctxts {
		if len(ctxt) > longestLen {
			longestLen = len(ctxt)
		}
	}
	bs := 1
	for i := 0; i < longestLen; i += bs {
		var column []byte
		for _, ctxt := range ctxts {
			if (i + bs) < len(ctxt) {
				column = append(column, ctxt[i:i+bs]...)
			}
		}
		xorKey = append(xorKey, findRepeatingXorKey(column, freqMap, bs)...)
	}
	return xorKey
}

//W ...
var W = 32

//N ...
const N = 624

//M ...
var M = 397

//R ...
var R = 31

//A ...
var A = 0x9908B0DF

//F ...
var F = 1812433253

//U ...
var U = 11

//D ...
var D = 0xFFFFFFFF

//S ...
var S = 7

//B ...
var B = 0x9D2C5680

//T ...
var T = 15

//C ...
var C = 0xEFC60000

//L ...
var L = 18

//MaskLower ...
var MaskLower = (1 << uint32(R)) - 1

//MaskUpper ...
var MaskUpper = (1 << uint32(R))

type mt19937 struct {
	MT    [N]uint32
	index int
}

// Initialize the generator from a seed
func initializeMT19937(seed uint32) *mt19937 {
	m := &mt19937{index: N}

	m.MT[0] = seed

	for i := 1; i < N; i++ {
		m.MT[i] = uint32(F)*(m.MT[i-1]^(m.MT[i-1]>>30)) + uint32(i)
	}
	return m
}

// Extract a tempered value based on MT[index]
// calling twist() every n numbers
func (m *mt19937) extractNumber() uint32 {
	if m.index >= N {
		if m.index > N {
			panic("Generator was never seeded")
			// Alternatively, seed with constant value; 5489 is used in reference C code[48]
		}
		m.twist()
	}
	//fmt.Println("index after twist ", m.index)
	y := m.MT[m.index]
	y = y ^ (y >> (uint32(U)) & uint32(D))
	y = y ^ (y << (uint32(S)) & uint32(B))
	y = y ^ (y << (uint32(T)) & uint32(C))
	y = y ^ (y >> uint32(L))

	m.index = m.index + 1
	return y
}

// Generate the next n values from the series x_i
func (m *mt19937) twist() {
	for i := 0; i < N; i++ {
		x := (m.MT[i] & uint32(MaskUpper)) + (m.MT[(i+1)%N] & uint32(MaskLower))
		xA := x >> 1
		if (x % 2) != 0 { // lowest bit of x is 1
			xA = xA ^ uint32(A)
		}
		m.MT[i] = m.MT[(i+M)%N] ^ uint32(xA)
	}

	m.index = 0
}

func timeAsMT19937Seed() uint32 {
	time.Sleep(time.Millisecond * time.Duration(40+mathrand.Intn(1000-40)))
	originalSeed := time.Now().Unix()
	fmt.Println(originalSeed)
	return initializeMT19937(uint32(originalSeed)).extractNumber()
}

func crackMT19937Seed() uint32 {
	mt := timeAsMT19937Seed()
	testSeed := uint32(time.Now().Unix())
	for {
		if initializeMT19937(uint32(testSeed)).extractNumber() == mt {
			return testSeed
		}
		testSeed--
	}
}

func untemperMT19937(y uint32) uint32 {
	y = y ^ y>>18
	y = y ^ ((y << 15) & 4022730752)
	for i := 0; i < 7; i++ {
		y = y ^ (y << 7 & 0x9D2C5680)
	}
	y = y ^ y>>11 ^ y>>(11*2)
	return y
}
