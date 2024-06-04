package modfiysm2

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"hash"
	"io"
	"math/big"
)

var One = new(big.Int).SetInt64(1)

func BytesCombine(pBytes ...[]byte) []byte {
	var buffer bytes.Buffer
	for index := 0; index < len(pBytes); index++ {
		buffer.Write(pBytes[index])
	}
	return buffer.Bytes()
}

// 这里使用了"github.com/tjfoc/gmsm/sm2"的内置函数，将随机输入的random，变成k用于分享随机数
func RandFieldElement(C elliptic.Curve, random io.Reader) (k *big.Int, err error) {
	if random == nil {
		random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := C.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(random, b) //将random读到b中
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, One) // n = N-1
	k.Mod(k, n)
	k.Add(k, One)
	return
}

func Generatekey(C elliptic.Curve, random io.Reader) (*big.Int, *big.Int, *big.Int) {

	sk, _ := RandFieldElement(C, nil)

	//pk=(sk^-1-1)G
	skInv := new(big.Int).ModInverse(sk, C.Params().N)
	OneNeg := new(big.Int).Sub(C.Params().N, One)
	skInvAddOneNeg := new(big.Int).Add(skInv, OneNeg)
	pkx, pky := C.ScalarBaseMult(skInvAddOneNeg.Bytes())

	return sk, pkx, pky
}
func Sign(C elliptic.Curve, hash hash.Hash, Msg []byte, Z *big.Int, sk *big.Int, random io.Reader) (*big.Int, *big.Int) {
	hash.Write(BytesCombine(Z.Bytes(), Msg))
	bytes := hash.Sum(nil)

	e := new(big.Int).SetBytes(bytes)
	e = e.Mod(e, C.Params().N)
	hash.Reset()

	//计算随机数
	K, _ := RandFieldElement(C, random)
	KGx, _ := C.ScalarBaseMult(K.Bytes())

	//计算r
	r := new(big.Int).Add(KGx, e)
	r.Mod(r, C.Params().N)

	//计算s
	s := new(big.Int).Add(K, r)
	s.Mul(s, sk)
	s.Mod(s, C.Params().N)
	s.Sub(s, r)
	s.Mod(s, C.Params().N)

	return r, s

}

func Verify(C elliptic.Curve, hash hash.Hash, Msg []byte, Z *big.Int, pkx, pky *big.Int, r *big.Int, s *big.Int) bool {

	hash.Write(BytesCombine(Z.Bytes(), Msg))
	bytes := hash.Sum(nil)

	e := new(big.Int).SetBytes(bytes)
	e = e.Mod(e, C.Params().N)
	hash.Reset()

	//计算t = r + s mod N
	t := new(big.Int).Add(r, s)
	t.Mod(t, C.Params().N)

	//计算 rGx , _ = s * G + t * pk
	sGx, sGy := C.ScalarBaseMult(s.Bytes())
	tPkx, tPky := C.ScalarMult(pkx, pky, t.Bytes())
	rGx, _ := C.Add(sGx, sGy, tPkx, tPky)

	//计算rTemp = ( rGx + e) mod N
	rTemp := new(big.Int).Add(rGx, e)
	rTemp.Mod(rTemp, C.Params().N)

	return r.Cmp(rTemp) == 0
}

func ComputeZ(hash hash.Hash, Rtig *big.Int, Rho *big.Int, Xx *big.Int, Xy *big.Int) *big.Int {
	hash.Write(BytesCombine(Rtig.Bytes(), Rho.Bytes(), Xx.Bytes(), Xy.Bytes()))
	bytes := hash.Sum(nil)
	Z := new(big.Int).SetBytes(bytes)
	hash.Reset()
	return Z
}
