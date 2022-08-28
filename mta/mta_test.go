package mta

import (
	"fmt"
	"math/big"

	"testing"

	"github.com/lianghuiqiang9/smt/network"

	"github.com/lianghuiqiang9/smt/modfiysm2"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/tjfoc/gmsm/sm2"
)

func TestMtA(t *testing.T) {
	//选定初始化曲线
	C := sm2.P256Sm2()
	//确定参与方人数N<26
	N := 4
	//确定阈值T<=N
	T := 3
	//建立network
	var net = network.NewNetwork(nil, N, T, C)
	//初始化通信信道
	net.Init()
	//初始化秘密信息map，每个参与方只使用自己的的。
	SecertInfo := make(network.MSecretPartiesInfoMap)

	for i := 0; i < 2; i++ {
		SecretInfoi := new(network.SecretPartyInfo)
		paillierSecret := paillier.NewSecretKey(nil)
		paillierPublic := paillierSecret.PublicKey
		SecretInfoi.PaillierSecertKey = paillierSecret
		SecretInfoi.Xi, _ = modfiysm2.RandFieldElement(C, nil)
		SecretInfoi.Gammai, _ = modfiysm2.RandFieldElement(C, nil)
		G := new(safenum.Int).SetBig(SecretInfoi.Xi, SecretInfoi.Xi.BitLen())
		SecretInfoi.EncXi, _ = paillierPublic.Enc(G)

		net.Parties[i].PaillierPublickey = paillierPublic
		SecertInfo[string('a'+rune(i))] = SecretInfoi
	}

	a1 := SecertInfo["a"].Xi
	a2 := SecertInfo["b"].Xi
	b1 := SecertInfo["a"].Gammai
	b2 := SecertInfo["b"].Gammai

	a := new(big.Int).Add(a1, a2)
	b := new(big.Int).Add(b1, b2)
	c := new(big.Int).Mul(a, b)
	c.Mod(c, C.Params().N)

	a1safe := new(safenum.Int).SetBig(a1, a1.BitLen())
	a2safe := new(safenum.Int).SetBig(a2, a2.BitLen())

	Ea1, _ := net.Parties[0].PaillierPublickey.Enc(a1safe)
	Ea2, _ := net.Parties[1].PaillierPublickey.Enc(a2safe)

	//此时Ea2=b1*E(a2)+(-beta12)
	Beta12, _ := modfiysm2.RandFieldElement(C, nil)
	Beta12neg := new(big.Int).Neg(Beta12)
	Beta12negsafe := new(safenum.Int).SetBig(Beta12neg, Beta12neg.BitLen())
	EBeta12negsafe, _ := net.Parties[1].PaillierPublickey.Enc(Beta12negsafe)

	b1safe := new(safenum.Int).SetBig(b1, b1.BitLen())
	Ea2.Mul(net.Parties[1].PaillierPublickey, b1safe)
	Ea2.Add(net.Parties[1].PaillierPublickey, EBeta12negsafe)

	Beta21, _ := modfiysm2.RandFieldElement(C, nil)
	Beta21neg := new(big.Int).Neg(Beta21)
	Beta21negsafe := new(safenum.Int).SetBig(Beta21neg, Beta21neg.BitLen())
	EBeta21negsafe, _ := net.Parties[0].PaillierPublickey.Enc(Beta21negsafe)

	//Ea1=b2*E(a1)+(-beta21)
	b2safe := new(safenum.Int).SetBig(b2, b2.BitLen())
	Ea1.Mul(net.Parties[0].PaillierPublickey, b2safe)
	Ea1.Add(net.Parties[0].PaillierPublickey, EBeta21negsafe)

	alpha21, _ := SecertInfo["b"].PaillierSecertKey.Dec(Ea2)
	alpha12, _ := SecertInfo["a"].PaillierSecertKey.Dec(Ea1)
	alpha211 := alpha21.Abs().Big()
	alpha122 := alpha12.Abs().Big()

	a1b1 := new(big.Int).Mul(a1, b1)
	a2b2 := new(big.Int).Mul(a2, b2)

	c2 := new(big.Int)
	c2.Add(c2, a1b1)
	c2.Add(c2, a2b2)
	c2.Add(c2, alpha211)
	c2.Add(c2, alpha122)
	c2.Add(c2, Beta12)
	c2.Add(c2, Beta21)
	c2.Mod(c2, C.Params().N)
	fmt.Println("a*b,c2", c, c2)
	fmt.Println(c.Cmp(c2) == 0)
}

/*	a1, _ := new(big.Int).SetString("3", 0)
	a2, _ := new(big.Int).SetString("4", 0)
	b1, _ := new(big.Int).SetString("5", 0)
	b2, _ := new(big.Int).SetString("6", 0)
	Beta12, _ := new(big.Int).SetString("7", 0)
	Beta21, _ := new(big.Int).SetString("8", 0)
*/
