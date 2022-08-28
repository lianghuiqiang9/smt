package modfiysm2

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"hash"

	"github.com/lianghuiqiang9/smt/network"

	"io"
	"math/big"
)

var one = new(big.Int).SetInt64(1) //将1变成大数

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
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func Generatekey(C elliptic.Curve, random io.Reader) (*big.Int, *big.Int, *big.Int) {
	//sk为私钥
	sk, _ := RandFieldElement(C, nil)

	//pk作为公钥pk=(sk^-1-1)G
	skInv := new(big.Int).ModInverse(sk, C.Params().N)
	oneNeg := new(big.Int).Sub(C.Params().N, one)
	skTnvaddoneNeg := new(big.Int).Add(skInv, oneNeg)
	pkx, pky := C.ScalarBaseMult(skTnvaddoneNeg.Bytes())

	return sk, pkx, pky
}
func Sign(C elliptic.Curve, hash hash.Hash, msg []byte, sk *big.Int, random io.Reader) (*big.Int, *big.Int) {
	hash.Write(msg)
	bytes := hash.Sum(nil)
	//将hash映射到椭圆曲线阶上。
	e := new(big.Int).SetBytes(bytes)
	e = e.Mod(e, C.Params().N)
	hash.Reset() //要养成一个良好的习惯。

	//计算随机数
	k, _ := RandFieldElement(C, random)
	Rx, _ := C.ScalarBaseMult(k.Bytes())

	//计算r
	r := new(big.Int).Add(Rx, e)
	r.Mod(r, C.Params().N)
	//计算s
	s := new(big.Int).Add(k, r)
	s.Mul(s, sk)
	s.Mod(s, C.Params().N)
	s.Sub(s, r)
	s.Mod(s, C.Params().N)

	return r, s

}

func Verify(C elliptic.Curve, hash hash.Hash, msg []byte, Z *big.Int, pkx, pky *big.Int, r *big.Int, s *big.Int) bool {

	hash.Write(BytesCombine(Z.Bytes(), msg))
	bytes := hash.Sum(nil)
	//将hash映射到椭圆曲线阶上。
	e2 := new(big.Int).SetBytes(bytes)
	e2 = e2.Mod(e2, C.Params().N)
	hash.Reset() //要养成一个良好的习惯。

	//计算t
	t1 := new(big.Int).Add(r, s)
	t1.Mod(t1, C.Params().N)

	//计算sG+tpk
	SGx, SGy := C.ScalarBaseMult(s.Bytes())
	TXx, TXy := C.ScalarMult(pkx, pky, t1.Bytes())
	Rx1, _ := C.Add(SGx, SGy, TXx, TXy)

	//计算r1=(rx+e)modN
	r1 := new(big.Int).Add(Rx1, e2)
	r1.Mod(r1, C.Params().N)

	return r.Cmp(r1) == 0
}

func ComputeZ(hash hash.Hash, party *network.Party) *big.Int {
	hash.Write(BytesCombine(party.Rtig.Bytes(), party.Rho.Bytes(), party.Xx.Bytes(), party.Xy.Bytes()))
	bytes := hash.Sum(nil)
	Z := new(big.Int).SetBytes(bytes)
	hash.Reset()
	return Z
}
