package cryptopals

import (
	"bytes"
	"crypto/hmac"
	cryptosha1 "crypto/sha1"
	"crypto/sha256"
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

func Test36(t *testing.T) {
	srpParams := new(srpCSParams)
	srpParams.g = big.NewInt(2)
	srpParams.k = big.NewInt(3)
	srpParams.I = "email"
	srpParams.P = "pwd"
	srpParams.N, _ = new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)

	fmt.Println("srp params initialized")

	srpSrvr := new(srpServer)
	srpSrvr.params = srpParams
	srpSrvr.newSrpServer()

	fmt.Println("srp server initialized")

	srpA := new(srpClient)
	srpA.params = srpParams
	srpA.pvt = getSrpPrivateKey(srpA.params.N)
	srpA.pub = getSrpPublicKey(srpA.params.g, srpA.params.N, srpA.pvt)

	fmt.Println("srp client initialized")

	uH := sha256.Sum256(append(srpA.pub.Bytes(), srpSrvr.pub.Bytes()...))
	u := new(big.Int).SetBytes(uH[:])

	fmt.Println("client to generate hash")

	generateClientHash := func() []byte {
		salt := srpSrvr.salt
		xH := sha256.Sum256(append(salt, []byte(srpA.params.P)...))
		x := new(big.Int).SetBytes(xH[:])
		//S = (B - k * g**x)**(a + u * x) % N
		// (a + u * x) % N
		tmp1 := new(big.Int).Mul(u, x)
		tmp1.Add(tmp1, srpA.pvt)
		tmp1.Mod(tmp1, srpA.params.N)
		//(B - k * g**x)
		tmp2 := new(big.Int).Exp(srpA.params.g, x, srpA.params.N)
		tmp2.Mul(srpA.params.k, tmp2)
		tmp2.Sub(srpSrvr.pub, tmp2)
		SClient := new(big.Int).Exp(tmp2, tmp1, srpA.params.N)
		KClient := sha256.Sum256(SClient.Bytes())
		hash := hmac.New(sha256.New, KClient[:])
		hash.Write(salt)
		return hash.Sum(nil)
	}

	fmt.Println("server to generate hash")

	generateServerHash := func() []byte {
		//SServer = (A * v**u) ** b % N
		SServer := new(big.Int).Exp(srpSrvr.v, u, srpSrvr.params.N)
		SServer.Mul(SServer, srpA.pub)
		SServer.Exp(SServer, srpSrvr.pvt, srpSrvr.params.N)
		KServer := sha256.Sum256(SServer.Bytes())
		hash := hmac.New(sha256.New, KServer[:])
		hash.Write(srpSrvr.salt)
		return hash.Sum(nil)
	}

	fmt.Println(bytes.Equal(generateServerHash(), generateClientHash()))
}
