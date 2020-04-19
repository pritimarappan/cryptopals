package cryptopals

import (
	"fmt"
	"math/big"
	"testing"
)

func Test33(t *testing.T) {
	var p, _ = new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	g := big.NewInt(2)

	dhp := new(dhParams)
	dhp.g = g
	dhp.p = p
	dha := new(dhKeys)
	dhb := new(dhKeys)
	dha.getDhPrivateKey(dhp.p)
	dha.getDhPublicKey(dhp)
	dhb.getDhPrivateKey(dhp.p)
	dhb.getDhPublicKey(dhp)
	sa := getDhSecret(dhp.p, dhb.pub, dha.pvt)
	sb := getDhSecret(dhp.p, dha.pub, dha.pvt)
	fmt.Println(sa.Cmp(sb))
}
