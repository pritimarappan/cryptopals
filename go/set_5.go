package cryptopals

import (
	"crypto/rand"
	"math/big"
)

type dhParams struct {
	p, g *big.Int
}

type dhKeys struct {
	pvt, pub *big.Int
}

func (dhk *dhKeys) getDhPublicKey(dhp *dhParams) {
	dhk.pub = new(big.Int).Exp(dhp.g, dhk.pvt, dhp.p)
}

func (dhk *dhKeys) getDhPrivateKey(p *big.Int) {
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
