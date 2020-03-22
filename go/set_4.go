package cryptopals

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

func getctrOracles() (
	ctrEncryptionOracle func([]byte) []byte,
	ctrEditnOracle func([]byte, int, []byte) []byte,
) {
	encryptionKey := generateRandomBytes(BLOCKSIZE)
	nonce := make([]byte, 8)

	ctrEncryptionOracle = func(in []byte) []byte {
		return aesCtrEncrypt(in, encryptionKey, nonce)
	}
	ctrEditnOracle = func(ciphertext []byte, offset int, newText []byte) []byte {
		ptxt := aesCtrDecrypt(ciphertext, encryptionKey, nonce)
		ptxt = append(append(ptxt[0:offset], newText...), ptxt[offset+len(newText):]...)
		return aesCtrEncrypt(ptxt, encryptionKey, nonce)
	}
	return
}

func getCtrOracles() (
	generateCookie func([]byte) []byte,
	isAdmin func([]byte) bool,
) {
	encryptionKey := generateRandomBytes(BLOCKSIZE)
	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"
	nonce := generateRandomBytes(BLOCKSIZE)
	generateCookie = func(in []byte) []byte {
		encodedIn := bytes.Replace(in, []byte("="), []byte("%3D"), -1)
		encodedIn = bytes.Replace(encodedIn, []byte(";"), []byte("%3B"), -1)
		msg := append(append([]byte(prefix), encodedIn...), []byte(suffix)...)
		//msg = pkcs7Padding(msg, BLOCKSIZE)
		return aesCtrEncrypt(msg, encryptionKey, nonce)
		//return aesCbcEncrypt(msg, encryptionKey, iv)
	}

	isAdmin = func(in []byte) bool {
		decryptedProfileArr := aesCtrDecrypt(in, encryptionKey, nonce)
		decryptedProfile := string(decryptedProfileArr)
		fmt.Println(decryptedProfile)
		return strings.Contains(decryptedProfile, ";admin=true;")
	}
	return
}

func makeCtrAdminCookie(generateCookie func([]byte) []byte) []byte {
	//comment1=cooking%20MCs;userdata=AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA
	prefix := "comment1=cooking%20MCs;userdata="
	target := "AA;admin=true;AA"
	msg := bytes.Repeat([]byte{'A'}, 16*2)
	out := generateCookie(msg)
	block1 := out[:len(prefix)]                 //comment1=cooking%20MCs;userdata=
	block2 := out[len(prefix) : len(prefix)+16] //AAAAAAAAAAAAAAAA
	block3 := out[len(prefix)+16:]              //";comment2=%20like%20a%20pound%20of%20bacon"
	block2 = xor(block2, xor(bytes.Repeat([]byte{'A'}, 16), []byte(target)))
	return append(append(block1, block2...), block3...)
}

func getCbcOraclesWithKeyAsIv() (
	encryptMsg func([]byte) []byte,
	decryptMsg func([]byte) string,
) {
	encryptionKey := generateRandomBytes(BLOCKSIZE)
	iv := encryptionKey
	encryptMsg = func(in []byte) []byte {
		msg := pkcs7Padding(in, BLOCKSIZE)
		return aesCbcEncrypt(msg, encryptionKey, iv)
	}

	decryptMsg = func(ctxt []byte) string {
		decryptedProfileArr, _ := pkcs7UnPadding(aesCbcDecrypt(ctxt, encryptionKey, iv))
		decryptedProfile := string(decryptedProfileArr)

		if !regexp.MustCompile(`^[ -~]+$`).Match(decryptedProfileArr) { //regex doesn't match for ascii printable chars
			return ("invalid message: " + decryptedProfile)
		}
		return ""
	}
	return
}

//-----------------------  SHA-1 ---------------------------

//Size of a SHA-1 checksum in bytes.
const Size = 20

// BlockSize of SHA-1 in bytes.
const BlockSize = 64

const (
	chunk = 64
	init0 = 0x67452301
	init1 = 0xEFCDAB89
	init2 = 0x98BADCFE
	init3 = 0x10325476
	init4 = 0xC3D2E1F0
)

// sha1 represents the partial evaluation of a checksum.
type sha1 struct {
	h   [5]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

const (
	magic         = "sha\x01"
	marshaledSize = len(magic) + 5*4 + chunk + 8
)

func (d *sha1) MarshalBinary() ([]byte, error) {
	b := make([]byte, 0, marshaledSize)
	b = append(b, magic...)
	b = appendUint32(b, d.h[0])
	b = appendUint32(b, d.h[1])
	b = appendUint32(b, d.h[2])
	b = appendUint32(b, d.h[3])
	b = appendUint32(b, d.h[4])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, d.len)
	return b, nil
}

func (d *sha1) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic) || string(b[:len(magic)]) != magic {
		return errors.New("crypto/sha1: invalid hash state identifier")
	}
	if len(b) != marshaledSize {
		return errors.New("crypto/sha1: invalid hash state size")
	}
	b = b[len(magic):]
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	b, d.len = consumeUint64(b)
	d.nx = int(d.len % chunk)
	return nil
}

func appendUint64(b []byte, x uint64) []byte {
	var a [8]byte
	putUint64(a[:], x)
	return append(b, a[:]...)
}

func appendUint32(b []byte, x uint32) []byte {
	var a [4]byte
	putUint32(a[:], x)
	return append(b, a[:]...)
}

func consumeUint64(b []byte) ([]byte, uint64) {
	_ = b[7]
	x := uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
	return b[8:], x
}

func consumeUint32(b []byte) ([]byte, uint32) {
	_ = b[3]
	x := uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	return b[4:], x
}

func (d *sha1) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.nx = 0
	d.len = 0
}

// NewSHA1 returns a new hash.Hash computing the SHA1 checksum. The Hash also
// implements encoding.BinaryMarshaler and encoding.BinaryUnmarshaler to
// marshal and unmarshal the internal state of the hash.
func newSHA1() *sha1 {
	d := new(sha1)
	d.Reset()
	return d
}

func (d *sha1) Size() int { return Size }

func (d *sha1) BlockSize() int { return BlockSize }

func (d *sha1) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			blockGeneric(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		blockGeneric(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *sha1) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	d0 := *d
	hash := d0.checkSum()
	return append(in, hash[:]...)
}

func (d *sha1) checkSum() [Size]byte {
	len := d.len
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}

	// Length in bits.
	len <<= 3
	putUint64(tmp[:], len)
	d.Write(tmp[0:8])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [Size]byte

	putUint32(digest[0:], d.h[0])
	putUint32(digest[4:], d.h[1])
	putUint32(digest[8:], d.h[2])
	putUint32(digest[12:], d.h[3])
	putUint32(digest[16:], d.h[4])

	return digest
}

// ConstantTimeSum computes the same result of Sum() but in constant time
func (d *sha1) ConstantTimeSum(in []byte) []byte {
	d0 := *d
	hash := d0.constSum()
	return append(in, hash[:]...)
}

func (d *sha1) constSum() [Size]byte {
	var length [8]byte
	l := d.len << 3
	for i := uint(0); i < 8; i++ {
		length[i] = byte(l >> (56 - 8*i))
	}

	nx := byte(d.nx)
	t := nx - 56                 // if nx < 56 then the MSB of t is one
	mask1b := byte(int8(t) >> 7) // mask1b is 0xFF iff one block is enough

	separator := byte(0x80) // gets reset to 0x00 once used
	for i := byte(0); i < chunk; i++ {
		mask := byte(int8(i-nx) >> 7) // 0x00 after the end of data

		// if we reached the end of the data, replace with 0x80 or 0x00
		d.x[i] = (^mask & separator) | (mask & d.x[i])

		// zero the separator once used
		separator &= mask

		if i >= 56 {
			// we might have to write the length here if all fit in one block
			d.x[i] |= mask1b & length[i-56]
		}
	}

	// compress, and only keep the digest if all fit in one block
	blockGeneric(d, d.x[:])

	var digest [Size]byte
	for i, s := range d.h {
		digest[i*4] = mask1b & byte(s>>24)
		digest[i*4+1] = mask1b & byte(s>>16)
		digest[i*4+2] = mask1b & byte(s>>8)
		digest[i*4+3] = mask1b & byte(s)
	}

	for i := byte(0); i < chunk; i++ {
		// second block, it's always past the end of data, might start with 0x80
		if i < 56 {
			d.x[i] = separator
			separator = 0
		} else {
			d.x[i] = length[i-56]
		}
	}

	// compress, and only keep the digest if we actually needed the second block
	blockGeneric(d, d.x[:])

	for i, s := range d.h {
		digest[i*4] |= ^mask1b & byte(s>>24)
		digest[i*4+1] |= ^mask1b & byte(s>>16)
		digest[i*4+2] |= ^mask1b & byte(s>>8)
		digest[i*4+3] |= ^mask1b & byte(s)
	}

	return digest
}

// Sum returns the SHA-1 checksum of the data.
func Sum(data []byte) [Size]byte {
	var d sha1
	d.Reset()
	d.Write(data)
	return d.checkSum()
}

func putUint64(x []byte, s uint64) {
	_ = x[7]
	x[0] = byte(s >> 56)
	x[1] = byte(s >> 48)
	x[2] = byte(s >> 40)
	x[3] = byte(s >> 32)
	x[4] = byte(s >> 24)
	x[5] = byte(s >> 16)
	x[6] = byte(s >> 8)
	x[7] = byte(s)
}

func putUint32(x []byte, s uint32) {
	_ = x[3]
	x[0] = byte(s >> 24)
	x[1] = byte(s >> 16)
	x[2] = byte(s >> 8)
	x[3] = byte(s)
}

const (
	_K0 = 0x5A827999
	_K1 = 0x6ED9EBA1
	_K2 = 0x8F1BBCDC
	_K3 = 0xCA62C1D6
)

// blockGeneric is a portable, pure Go version of the SHA-1 block step.
// It's used by sha1block_generic.go and tests.
func blockGeneric(dig *sha1, p []byte) {
	var w [16]uint32

	h0, h1, h2, h3, h4 := dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4]
	for len(p) >= chunk {
		// Can interlace the computation of w with the
		// rounds below if needed for speed.
		for i := 0; i < 16; i++ {
			j := i * 4
			w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
		}

		a, b, c, d, e := h0, h1, h2, h3, h4

		// Each of the four 20-iteration rounds
		// differs only in the computation of f and
		// the choice of K (_K0, _K1, etc).
		i := 0
		for ; i < 16; i++ {
			f := b&c | (^b)&d
			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K0
			a, b, c, d, e = t, a, b30, c, d
		}
		for ; i < 20; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)

			f := b&c | (^b)&d
			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K0
			a, b, c, d, e = t, a, b30, c, d
		}
		for ; i < 40; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)
			f := b ^ c ^ d
			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K1
			a, b, c, d, e = t, a, b30, c, d
		}
		for ; i < 60; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)
			f := ((b | c) & d) | (b & c)

			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K2
			a, b, c, d, e = t, a, b30, c, d
		}
		for ; i < 80; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)
			f := b ^ c ^ d
			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K3
			a, b, c, d, e = t, a, b30, c, d
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e

		p = p[chunk:]
	}

	dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4] = h0, h1, h2, h3, h4
}

//-------------------------- SHA-1 -----------------------------------

func getSecretPrefixSha1(key []byte, msg []byte) []byte {
	h := newSHA1()
	h.Write(key)
	h.Write(msg)
	mac := h.checkSum()
	return mac[:]
}

func verifySecretPrefixSha1(key []byte, msg []byte, mac []byte) bool {
	hash := getSecretPrefixSha1(key, msg)
	return bytes.Equal(hash[:], mac)
}

func computeMDPadding(len int) (padding []byte) {
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		padding = append(padding, tmp[0:56-len%64]...)
	} else {
		padding = append(padding, tmp[0:64+56-len%64]...)
	}

	// Length in bits.
	len <<= 3
	putUint64(tmp[:], uint64(len))
	padding = append(padding, tmp[0:8]...)
	return
}

func secretPrefixOracle() (
	cookie []byte,
	isAdmin func(cookie []byte) bool,
) {
	key := generateRandomBytes(16)
	msg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	hash := getSecretPrefixSha1(key, msg)
	cookie = append(append(cookie, hash...), msg...)

	isAdmin = func(in []byte) bool {
		mac, rcvdMsg := in[:20], in[20:]
		if !bytes.Equal(getSecretPrefixSha1(key, rcvdMsg), mac) {
			return false
		}
		return bytes.Contains(rcvdMsg, []byte(";admin=true;"))
	}
	return
}

func fixSha1Registers(in []byte) *sha1 {
	s := newSHA1()
	s.h[0] = binary.BigEndian.Uint32(in[:4])
	s.h[1] = binary.BigEndian.Uint32(in[4:8])
	s.h[2] = binary.BigEndian.Uint32(in[8:12])
	s.h[3] = binary.BigEndian.Uint32(in[12:16])
	s.h[4] = binary.BigEndian.Uint32(in[16:])
	return s
}

func attackSha1() {
	cookie, isAdmin := secretPrefixOracle()
	origMac, origMsg := cookie[:20], cookie[20:]
	keyLen := 16

	gluePadding := computeMDPadding(len(origMsg) + keyLen)

	s := fixSha1Registers(origMac)
	s.len = uint64(len(origMsg) + len(gluePadding) + keyLen)
	addMsg := []byte(";admin=true;")
	s.Write(addMsg)
	newMac := s.checkSum()

	var newMsg []byte
	newMsg = append(newMsg, origMsg...)
	newMsg = append(newMsg, gluePadding...)
	newMsg = append(newMsg, addMsg...)

	newCookie := append(newMac[:], newMsg...)

	if isAdmin(newCookie) {
		fmt.Println("attack successful")
	} else {
		fmt.Println("attack on SHA1 failed")
	}

}
