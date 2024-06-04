package mta

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/lianghuiqiang9/smt/modfiysm2"
	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/paillier"
	"github.com/tjfoc/gmsm/sm2"
)

func TestMtA(t *testing.T) {

	C := sm2.P256Sm2()
	//build network
	var net = network.NewNetwork(nil, 2, 2, C)
	net.Init()

	//init secert map。
	SecertInfo := make(network.MSecretPartiesInfoMap)

	for i := 0; i < 2; i++ {
		SecretInfoi := new(network.SecretPartyInfo)

		paillierprivkey := paillier.NewSecretKey(nil)
		paillierpubkey := paillierprivkey.PublicKey

		SecretInfoi.PaillierSecertKey = paillierprivkey
		SecretInfoi.Xi, _ = modfiysm2.RandFieldElement(C, nil)
		SecretInfoi.Gammai, _ = modfiysm2.RandFieldElement(C, nil)
		SecretInfoi.EncXi, _ = paillierpubkey.Enc2(SecretInfoi.Xi)
		SecertInfo[string('a'+rune(i))] = SecretInfoi

		net.Parties[i].PaillierPublickey = paillierpubkey

	}

	a1 := SecertInfo["a"].Xi
	a2 := SecertInfo["b"].Xi
	b1 := SecertInfo["a"].Gammai
	b2 := SecertInfo["b"].Gammai

	a := new(big.Int).Add(a1, a2)
	b := new(big.Int).Add(b1, b2)
	c := new(big.Int).Mul(a, b)
	c.Mod(c, C.Params().N)

	Ea1, _ := net.Parties[0].PaillierPublickey.Enc2(a1)
	Ea2, _ := net.Parties[1].PaillierPublickey.Enc2(a2)

	// Ea2 = b1 * E(a2) + (-beta12)
	Beta12, _ := modfiysm2.RandFieldElement(C, nil)
	Beta12neg := new(big.Int).Neg(Beta12)
	Beta12neg.Mod(Beta12neg, C.Params().N)
	EBeta12negsafe, _ := net.Parties[1].PaillierPublickey.Enc2(Beta12neg)
	Ea2 = Ea2.Mul2(net.Parties[1].PaillierPublickey, b1)
	Ea2 = Ea2.Add2(net.Parties[1].PaillierPublickey, EBeta12negsafe)

	// Ea1 = b2 * E(a1) + (-beta21)
	Beta21, _ := modfiysm2.RandFieldElement(C, nil)
	Beta21neg := new(big.Int).Neg(Beta21)
	Beta21neg.Mod(Beta21neg, C.Params().N)
	EBeta21negsafe, _ := net.Parties[0].PaillierPublickey.Enc2(Beta21neg)
	Ea1 = Ea1.Mul2(net.Parties[0].PaillierPublickey, b2)
	Ea1 = Ea1.Add2(net.Parties[0].PaillierPublickey, EBeta21negsafe)

	alpha211, _ := SecertInfo["b"].PaillierSecertKey.Dec2(Ea2)
	alpha122, _ := SecertInfo["a"].PaillierSecertKey.Dec2(Ea1)
	alpha211.Mod(alpha211, C.Params().N)
	alpha122.Mod(alpha122, C.Params().N)

	a1b1 := new(big.Int).Mul(a1, b1)
	a2b2 := new(big.Int).Mul(a2, b2)

	cTemp := new(big.Int)
	cTemp.Add(cTemp, a1b1)
	cTemp.Add(cTemp, a2b2)
	cTemp.Add(cTemp, alpha211)
	cTemp.Add(cTemp, alpha122)
	cTemp.Add(cTemp, Beta12)
	cTemp.Add(cTemp, Beta21)
	cTemp.Mod(cTemp, C.Params().N)

	fmt.Println(c.Cmp(cTemp) == 0)
}
