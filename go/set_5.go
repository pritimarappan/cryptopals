package cryptopals

import (
	"crypto/hmac"
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

func (srv *srpServer) newSimpleSrpServer(password string) {
	srv.newSrpServer(password)
	//B=kv + g**b % N
	srv.pub = new(big.Int).Exp(srv.params.g, srv.pvt, srv.params.N)
}

func (srp *srpCSParams) initSrpParams() {
	srp.g = big.NewInt(2)
	srp.k = big.NewInt(3)
	srp.I = "email"
	srp.N, _ = new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	fmt.Println("srp params initialized")
}

func (srp *srpCSParams) initSimpleSrpParams() {
	srp.initSrpParams()
	srp.k = big.NewInt(0)
}

func (srpc *srpClient) generateClientHash(salt []byte, password string, u *big.Int, serverPub *big.Int) []byte {
	xH := sha256.Sum256(append(salt, []byte(password)...))
	x := new(big.Int).SetBytes(xH[:])
	//S = (B - k * g**x)**(a + u * x) % N
	// (a + u * x) % N
	tmp1 := new(big.Int).Mul(u, x)
	tmp1.Add(tmp1, srpc.pvt)
	tmp1.Mod(tmp1, srpc.params.N)
	//(B - k * g**x)
	tmp2 := new(big.Int).Exp(srpc.params.g, x, srpc.params.N)
	tmp2.Mul(srpc.params.k, tmp2)
	tmp2.Sub(serverPub, tmp2)
	SClient := new(big.Int).Exp(tmp2, tmp1, srpc.params.N)
	KClient := sha256.Sum256(SClient.Bytes())
	hash := hmac.New(sha256.New, KClient[:])
	hash.Write(salt)
	return hash.Sum(nil)
}

func (srv *srpServer) generateServerHash(clientPub *big.Int, u *big.Int) []byte {
	//SServer = (A * v**u) ** b % N
	SServer := new(big.Int).Exp(srv.v, u, srv.params.N)
	SServer.Mul(SServer, clientPub)
	SServer.Exp(SServer, srv.pvt, srv.params.N)
	KServer := sha256.Sum256(SServer.Bytes())
	hash := hmac.New(sha256.New, KServer[:])
	hash.Write(srv.salt)
	return hash.Sum(nil)
}

type srpServerMITM struct {
	A, b, B   *big.Int
	salt, mac []byte
}

func (srv *srpServer) tryPassword(password []byte, cpub *big.Int, cHash []byte) bool {
	uH := sha256.Sum256(append(cpub.Bytes(), srv.pub.Bytes()...))
	u := new(big.Int).SetBytes(uH[:])

	xH := sha256.Sum256(append(srv.salt, password...))
	x := new(big.Int).SetBytes(xH[:])

	S := new(big.Int)
	S.Exp(srv.pub, u, srv.params.N)
	S.Exp(S, x, srv.params.N)
	S.Mul(S, new(big.Int).Exp(cpub, srv.pvt, srv.params.N))
	S.Mod(S, srv.params.N)

	K := sha256.Sum256(S.Bytes())
	h := hmac.New(sha256.New, K[:])
	h.Write(srv.salt)
	return hmac.Equal(h.Sum(nil), cHash)
}

type privateKey struct {
	//publicKey            // public part.
	D      *big.Int   // private exponent
	Primes []*big.Int // prime factors of N, has >= 2 elements.
	//Precomputed PrecomputedValues
}

type publicKey struct {
	N *big.Int // modulus
	E *big.Int // public exponent
}

type rsa struct {
	pvt *privateKey
	pub *publicKey
}

func (r *rsa) generateRsaKeys() {
	for {
		p, _ := rand.Prime(rand.Reader, 1024)
		q, _ := rand.Prime(rand.Reader, 1024)
		r.pvt = new(privateKey)
		r.pub = new(publicKey)
		r.pvt.Primes = []*big.Int{p, q}
		r.pub.N = new(big.Int).Mul(p, q)
		et := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
		r.pub.E = big.NewInt(3)
		r.pvt.D = modInverse(big.NewInt(3), et)
		//fmt.Println(" modinverse output ", r.pvt.D)
		if r.pvt.D != nil && r.pvt.D.Cmp(big.NewInt(1)) > 0 {
			break
		}
	}
}

func modInverse(a *big.Int, n *big.Int) *big.Int {
	//"""return x such that (x * a) % b == 1"""
	var d, x *big.Int
	d = new(big.Int)
	x = new(big.Int)
	z := d.GCD(x, nil, a, n)
	if d.Cmp(big.NewInt(1)) != 0 {
		//fmt.Println("gcd(a, b) != 1")
		return nil
	}

	// x and y are such that g*x + n*y = 1, therefore x is the inverse element,

	// but it may be negative, so convert to the range 0 <= z < |n|

	if x.Cmp(big.NewInt(0)) == -1 {

		z.Add(x, n)

	} else {

		z.Set(x)

	}

	return z

	//return x.Mod(x, n) //x % n
}

func (r *rsa) rsaEncrypt(m *big.Int) *big.Int {
	//c = m**e%n
	return new(big.Int).Exp(m, r.pub.E, r.pub.N)
}

func (r *rsa) rsaDecrypt(c *big.Int) *big.Int {
	//m = c**d%n
	//fmt.Println("1  ", r.pvt.D)
	//fmt.Println("2  ", r.pub.N)
	return new(big.Int).Exp(c, r.pvt.D, r.pub.N)
}

func cubeRoot(cube *big.Int) *big.Int {
	//adopted from mostlyharmless
	//https://stackoverflow.com/questions/31238262/is-there-a-go-function-for-obtaining-the-cube-root-of-a-big-integer

	x := new(big.Int).Rsh(cube, uint(cube.BitLen())/3) //mostlyharmless multiplies by 2 which I don't get
	if x.Sign() == 0 {
		panic("can't start from 0")
	}
	for {
		d := new(big.Int).Exp(x, big.NewInt(3), nil)
		d.Sub(d, cube)
		d.Div(d, big.NewInt(3))
		d.Div(d, x)
		d.Div(d, x)
		if d.Sign() == 0 {
			break
		}
		x.Sub(x, d)
	}
	for new(big.Int).Exp(x, big.NewInt(3), nil).Cmp(cube) < 0 {
		x.Add(x, big.NewInt(1))
	}
	for new(big.Int).Exp(x, big.NewInt(3), nil).Cmp(cube) > 0 {
		x.Sub(x, big.NewInt(1))
	}
	// Return the cube, rounded down.
	// if new(big.Int).Exp(x, big3, nil).Cmp(cube) != 0 {
	// 	panic("not a cube")
	// }
	return x
}

func cuberootBinarySearch(cube *big.Int) *big.Int {
	lo := big.NewInt(0)
	hi := cube

	for lo.Cmp(hi) < 0 {

		mid := new(big.Int).Add(lo, hi)

		mid = mid.Div(mid, big.NewInt(2))

		tmp := new(big.Int).Exp(mid, big.NewInt(3), nil)

		if tmp.Cmp(cube) < 0 {
			lo = mid.Add(mid, big.NewInt(1))
		} else {
			hi = mid
		}
	}
	return lo
}
