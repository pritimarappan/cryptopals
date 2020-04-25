package cryptopals

import (
	cryptosha1 "crypto/sha1"
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
	dha.setDhPrivateKey(dhp.p)
	dha.setDhPublicKey(dhp)
	dhb.setDhPrivateKey(dhp.p)
	dhb.setDhPublicKey(dhp)
	sa := getDhSecret(dhp.p, dhb.pub, dha.pvt)
	sb := getDhSecret(dhp.p, dha.pub, dha.pvt)
	fmt.Println(sa.Cmp(sb))
}

func Test34(t *testing.T) {
	var p, _ = new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	g := big.NewInt(2)

	dhp := new(dhParams)
	dhp.g = g
	dhp.p = p

	dha := new(dhKeys)
	dha.setDhPrivateKey(dhp.p)
	dha.setDhPublicKey(dhp)

	dhBot := new(dhEchoBot)
	dhBot.init(dhp, dha.pub)

	B := dhBot.dhk.pub

	sAB := getDhSecret(dhp.p, B, dha.pvt)

	iv := generateRandomBytes(16)
	hash := cryptosha1.Sum(sAB.Bytes())
	key := hash[:16]
	msg := []byte("Hello world")
	msg = pkcs7Padding(msg, BLOCKSIZE)
	ct := aesCbcEncrypt(msg, key, iv)

	echoedCt := dhBot.echo(append(ct, iv...))

	echoedPt := aesCbcDecrypt(echoedCt[:len(echoedCt)-16], key, echoedCt[len(echoedCt)-16:])
	echoedPt, _ = pkcs7UnPadding(echoedPt)
	fmt.Println(string(echoedPt))

	//with MITM
	dhBotMitm := new(dhEchoBot)
	dhBotMitm.init(dhp, dha.pub)

	dhBotMB := new(dhEchoBot)
	dhBotMB.init(dhp, p)

	sAM := getDhSecret(dhp.p, dhp.p, dha.pvt)
	iv = generateRandomBytes(16)
	hash = cryptosha1.Sum(sAM.Bytes())
	key = hash[:16]
	ct = aesCbcEncrypt(msg, key, iv)

	echoedCt = dhBotMB.echo(append(ct, iv...))

	echoedPt = aesCbcDecrypt(echoedCt[:len(echoedCt)-16], key, echoedCt[len(echoedCt)-16:])
	echoedPt, _ = pkcs7UnPadding(echoedPt)
	fmt.Println(string(echoedPt))

}

func Test35(t *testing.T) {
	var p, _ = new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	g := big.NewInt(2)

	dhp := new(dhParams)
	dhp.g = g
	dhp.p = p
	dha := new(dhKeys)
	dha.setDhPrivateKey(dhp.p)
	dha.setDhPublicKey(dhp)

	dhpMitm := new(dhParams)
	dhpMitm.p = p
	dhb := new(dhKeys)

	//g =1
	fmt.Println("g=1")
	dhpMitm.g = big.NewInt(1)

	dhb.setDhPrivateKey(dhpMitm.p)
	dhb.setDhPublicKey(dhpMitm)
	sa := getDhSecret(dhp.p, dhb.pub, dha.pvt)
	fmt.Println(sa)

	//g=p
	fmt.Println("g=p")
	dhpMitm.g = p

	dhb.setDhPrivateKey(dhpMitm.p)
	dhb.setDhPublicKey(dhpMitm)
	sa = getDhSecret(dhp.p, dhb.pub, dha.pvt)
	fmt.Println(sa)

	//g=p-1
	fmt.Println("g=p-1")
	dhpMitm.g = new(big.Int).Sub(p, big.NewInt(1))

	dhb.setDhPrivateKey(dhpMitm.p)
	dhb.setDhPublicKey(dhpMitm)
	sa = getDhSecret(dhp.p, dhb.pub, dha.pvt)
	fmt.Println(sa)
}
