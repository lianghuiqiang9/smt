package mta

import (
	"fmt"
	"math/big"

	"testing"

	"github.com/lianghuiqiang9/smt/network"

	"github.com/lianghuiqiang9/smt/modfiysm2"

	//	paillierbig "github.com/roasbeef/go-go-gadget-paillier"
	"github.com/lianghuiqiang9/smt/paillier"
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

		//		paillierSecret := paillier.NewSecretKey(nil)
		//		paillierPublic := paillierSecret.PublicKey

		paillierprivkey := paillier.NewSecretKey(nil)
		paillierpubkey := paillierprivkey.PublicKey

		//		SecretInfoi.PaillierSecertKey = paillierSecret
		SecretInfoi.PaillierSecertKey = paillierprivkey

		SecretInfoi.Xi, _ = modfiysm2.RandFieldElement(C, nil)
		SecretInfoi.Gammai, _ = modfiysm2.RandFieldElement(C, nil)
		//		G := new(safenum.Int).SetBig(SecretInfoi.Xi, SecretInfoi.Xi.BitLen())
		//		SecretInfoi.EncXi, _ = paillierPublic.Enc(G)

		c, _ := paillierpubkey.Enc1(SecretInfoi.Xi)

		SecretInfoi.EncXi = c

		net.Parties[i].PaillierPublickey = paillierpubkey
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

	//	a1safe := new(safenum.Int).SetBig(a1, a1.BitLen())
	//	a2safe := new(safenum.Int).SetBig(a2, a2.BitLen())

	//	Ea1, _ := net.Parties[0].PaillierPublickey.Enc(a1safe)
	//	Ea2, _ := net.Parties[1].PaillierPublickey.Enc(a2safe)
	Ea1, _ := net.Parties[0].PaillierPublickey.Enc1(a1)
	Ea2, _ := net.Parties[1].PaillierPublickey.Enc1(a2)

	Da1, _ := SecertInfo["a"].PaillierSecertKey.Dec1(Ea1)
	Da2, _ := SecertInfo["b"].PaillierSecertKey.Dec1(Ea2)
	fmt.Println("Da1,Da2", Da1, Da2)
	//此时Ea2=b1*E(a2)+(-beta12)
	Beta12, _ := modfiysm2.RandFieldElement(C, nil)
	Beta12neg := new(big.Int).Neg(Beta12)
	Beta12neg.Mod(Beta12neg, C.Params().N)

	fmt.Println("Beta12neg", Beta12, C.Params().N, Beta12neg, Beta12neg.Bytes())
	// Beta12negsafe := new(safenum.Int).SetBig(Beta12neg, Beta12neg.BitLen())
	// EBeta12negsafe, _ := net.Parties[1].PaillierPublickey.Enc(Beta12negsafe)
	EBeta12negsafe, _ := net.Parties[1].PaillierPublickey.Enc1(Beta12neg)
	DBeta12negsafe, _ := SecertInfo["b"].PaillierSecertKey.Dec1(EBeta12negsafe)
	fmt.Println("DBeta12negsafe", DBeta12negsafe)
	// b1safe := new(safenum.Int).SetBig(b1, b1.BitLen())
	// Ea2.Mul(net.Parties[1].PaillierPublickey, b1safe)
	// Ea2.Add(net.Parties[1].PaillierPublickey, EBeta12negsafe)
	Ea2 = Ea2.Mul1(net.Parties[1].PaillierPublickey, b1)
	Da22, _ := SecertInfo["b"].PaillierSecertKey.Dec1(Ea2)
	fmt.Println("Da22,EBeta12negsafe", Da22, DBeta12negsafe)
	Ea2 = Ea2.AddCipher(net.Parties[1].PaillierPublickey, EBeta12negsafe)
	Da222, _ := SecertInfo["b"].PaillierSecertKey.Dec1(Ea2)
	Da2222 := new(big.Int).Mod(Da222, C.Params().N)
	fmt.Println("Da2222", Da2222)
	Beta21, _ := modfiysm2.RandFieldElement(C, nil)
	Beta21neg := new(big.Int).Neg(Beta21)
	fmt.Println("Beta21neg", Beta21neg)
	Beta21neg.Mod(Beta21neg, C.Params().N)
	fmt.Println("Beta21neg2", Beta21neg.Bytes())
	// Beta21negsafe := new(safenum.Int).SetBig(Beta21neg, Beta21neg.BitLen())
	// EBeta21negsafe, _ := net.Parties[0].PaillierPublickey.Enc(Beta21negsafe)
	EBeta21negsafe, _ := net.Parties[0].PaillierPublickey.Enc1(Beta21neg)
	DBeta21negsafe, _ := SecertInfo["a"].PaillierSecertKey.Dec1(EBeta21negsafe)
	fmt.Println("DBeta21negsafe", DBeta21negsafe)

	//Ea1=b2*E(a1)+(-beta21)
	//	b2safe := new(safenum.Int).SetBig(b2, b2.BitLen())
	//	Ea1.Mul(net.Parties[0].PaillierPublickey, b2safe)
	//	Ea1.Add(net.Parties[0].PaillierPublickey, EBeta21negsafe)
	Ea1 = Ea1.Mul1(net.Parties[0].PaillierPublickey, b2)
	Ea1 = Ea1.AddCipher(net.Parties[0].PaillierPublickey, EBeta21negsafe)

	// alpha21, _ := SecertInfo["b"].PaillierSecertKey.Dec(Ea2)
	// alpha12, _ := SecertInfo["a"].PaillierSecertKey.Dec(Ea1)
	alpha211, _ := SecertInfo["b"].PaillierSecertKey.Dec1(Ea2)
	alpha122, _ := SecertInfo["a"].PaillierSecertKey.Dec1(Ea1)
	//	alpha211 = alpha211.Abs(alpha211)
	//	alpha122 = alpha122.Abs(alpha122)
	alpha211.Mod(alpha211, C.Params().N)
	alpha122.Mod(alpha122, C.Params().N)
	fmt.Println("alpha211,alpha122", alpha211, alpha122)

	a1b1 := new(big.Int).Mul(a1, b1)
	a2b2 := new(big.Int).Mul(a2, b2)
	fmt.Println("a1b1,a2b2", a1b1, a2b2)
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
