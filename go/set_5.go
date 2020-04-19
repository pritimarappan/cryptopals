package cryptopals

import (
	"crypto/rand"
	cryptosha1 "crypto/sha1"
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
