package cryptopals

import (
	"crypto/rand"
	cryptosha1 "crypto/sha1"
	"crypto/sha256"
	"fmt"
	"math/big"
)

type dhParams struct {
	p, g *big.Int
}

type dhKeys struct {
	pvt, pub *big.Int
}

func (dhk *dhKeys) setDhPublicKey(dhp *dhParams) {
	dhk.pub = new(big.Int).Exp(dhp.g, dhk.pvt, dhp.p)
}

func (dhk *dhKeys) setDhPrivateKey(p *big.Int) {
	pvt, err := rand.Int(rand.Reader, p)
	if err != nil {
		panic(err)
	}
	dhk.pvt = pvt
}

func getDhSecret(p *big.Int, pub *big.Int, pvt *big.Int) *big.Int {
	s := new(big.Int).Exp(pub, pvt, p)
	return s
}

type dhEchoBot struct {
	dhp    *dhParams
	dhk    *dhKeys
	Secret *big.Int
}

func (dhBot *dhEchoBot) init(dhp *dhParams, pubA *big.Int) {
	dhBot.dhp = dhp
	dhBot.dhk = new(dhKeys)
	dhBot.dhk.setDhPrivateKey(dhp.p)
	dhBot.dhk.setDhPublicKey(dhp)
	dhBot.Secret = getDhSecret(dhp.p, pubA, dhBot.dhk.pvt)
}

func (dhBot *dhEchoBot) echo(in []byte) []byte {
	hash := cryptosha1.Sum(dhBot.Secret.Bytes())
	key := hash[:16]
	pt := aesCbcDecrypt(in[:len(in)-16], key, in[len(in)-16:])
	fmt.Println(string(pt))
	iv := generateRandomBytes(16)
	ct := aesCbcEncrypt(pt, key, iv)
	return append(ct, iv...)
}

type srpCSParams struct {
	N, g *big.Int
	I    string
	k    *big.Int
}

type srpServer struct {
	params   *srpCSParams
	salt     []byte
	v        *big.Int
	pub, pvt *big.Int
}

func (srv *srpServer) newSrpServer(password string) {
	salt := generateRandomBytes(16)
	srv.salt = salt
	xH := sha256.Sum256(append(salt, []byte(password)...))
	x := new(big.Int).SetBytes(xH[:])
	//v=g**x % N
	srv.v = new(big.Int).Exp(srv.params.g, x, srv.params.N)
	srv.pvt = getSrpPrivateKey(srv.params.N)
	//B=kv + g**b % N
	srv.pub = new(big.Int).Mul(srv.params.k, srv.v)
	srv.pub.Add(srv.pub, getSrpPublicKey(srv.params.g, srv.params.N, srv.pvt))
	srv.pub.Mod(srv.pub, srv.params.N)
}

type srpClient struct {
	params   *srpCSParams
	pub, pvt *big.Int
}

func getSrpPublicKey(g *big.Int, p *big.Int, pvt *big.Int) *big.Int {
	return new(big.Int).Exp(g, pvt, p)
}

func getSrpPrivateKey(p *big.Int) *big.Int {
	pvt, err := rand.Int(rand.Reader, p)
	if err != nil {
		panic(err)
	}
	return pvt
}
