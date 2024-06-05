package vss

import (
	"fmt"
	"math/big"

	"github.com/cronokirby/safenum"
	"github.com/lianghuiqiang9/smt/modfiysm2"
	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/paillier"
)

// 不失去一般性，我们取签名方为第0方到第T-1方。如需拓展，还需要结合签名方，来计算对应的lagrange系数
// id属于0到T-1。
func Lagrange(Net *network.Network, id string, T int) *big.Int {
	N := Net.Parties[0].Curve.Params().N
	i := 0
	xi := new(big.Int)
	for key, partyi := range Net.Parties {
		if partyi.ID == id {
			xi = partyi.Rtigi
			i = key
		}
	}

	xj := new(big.Int)
	A, _ := new(big.Int).SetString("1", 0)
	B, _ := new(big.Int).SetString("1", 0)
	//这里总是假设去前T个。
	for key := 0; key < T; key++ {
		if key != i {
			//计算每一项
			xj = xj.Neg(Net.Parties[key].Rtigi)
			A.Mul(A, xj)
			A.Mod(A, N)
			xj.Add(xj, xi)
			B.Mul(B, xj)
			B.Mod(B, N)
		}
	}
	B.ModInverse(B, N)
	B.Mul(B, A)
	B.Mod(B, N)
	return B
}

func VssShareWithEncy(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	Vssa := make(map[int]*big.Int)
	VssAx := make(map[int]*big.Int)
	VssAy := make(map[int]*big.Int)
	for i := 1; i < party.T; i++ {
		Vssa[i], _ = modfiysm2.RandFieldElement(party.Curve, nil)
		VssAx[i], VssAy[i] = party.Curve.ScalarBaseMult(Vssa[i].Bytes())
	}

	Vssy := make(map[string]*big.Int)
	VssEncy := make(map[string]*paillier.Ciphertext)
	for _, partyi := range Net.Parties {

		yi := new(big.Int)
		di := new(big.Int).Set(partyi.Rtigi)
		temp := new(big.Int)
		for key := 1; key < party.T; key++ {
			temp.Mul(di, Vssa[key])
			temp.Mod(temp, party.Curve.Params().N)
			yi.Add(yi, temp)
			di.Mul(di, partyi.Rtigi)
			di.Mod(di, party.Curve.Params().N)
		}
		yi.Add(yi, SecretInfo[party.ID].Xi)
		yi.Mod(yi, party.Curve.Params().N)
		Vssy[partyi.ID] = yi

		yiSafe := new(safenum.Int).SetBig(yi, yi.BitLen())

		ctyiSafe, _ := partyi.PaillierPublickey.Enc(yiSafe)
		VssEncy[partyi.ID] = ctyiSafe

	}

	SecretInfo[party.ID].Vssa = Vssa
	SecretInfo[party.ID].VssAx = VssAx
	SecretInfo[party.ID].VssAy = VssAy
	SecretInfo[party.ID].Vssy = Vssy
	SecretInfo[party.ID].VssEncy = VssEncy

}

func VssShare(Net *network.Network, SecertInfo network.MSecretPartiesInfoMap, N int, T int) {

	party := Net.Parties[0]
	for i := 0; i < N; i++ {
		Vssa := make(map[int]*big.Int)
		VssAx := make(map[int]*big.Int)
		VssAy := make(map[int]*big.Int)

		for i := 1; i < party.T; i++ {
			Vssa[i], _ = modfiysm2.RandFieldElement(party.Curve, nil)

			VssAx[i], VssAy[i] = party.Curve.ScalarBaseMult(Vssa[i].Bytes())
		}

		Vssy := make(map[string]*big.Int)

		for _, partyi := range Net.Parties {

			yi := new(big.Int)
			di := new(big.Int).Set(partyi.Rtigi)
			temp := new(big.Int)

			for key := 1; key < T; key++ {
				temp.Mul(di, Vssa[key])
				temp.Mod(temp, party.Curve.Params().N)

				yi.Add(yi, temp)

				di.Mul(di, partyi.Rtigi)
				di.Mod(di, party.Curve.Params().N)
			}

			yi.Add(yi, SecertInfo[Net.Parties[i].ID].Xi)
			yi.Mod(yi, party.Curve.Params().N)

			Vssy[partyi.ID] = yi

		}

		SecertInfo[Net.Parties[i].ID].Vssa = Vssa
		SecertInfo[Net.Parties[i].ID].VssAx = VssAx
		SecertInfo[Net.Parties[i].ID].VssAy = VssAy
		SecertInfo[Net.Parties[i].ID].Vssy = Vssy
	}
}

func VssVerifySingleParty(FromNum int, yij *big.Int, VssAx map[int]*big.Int, VssAy map[int]*big.Int, party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {

	Yijx, Yijy := party.Curve.ScalarBaseMult(yij.Bytes())

	yix := new(big.Int)
	yiy := new(big.Int)
	di := new(big.Int).Set(party.Rtigi)
	tempx := new(big.Int)
	tempy := new(big.Int)

	for key := 1; key < party.T; key++ {
		tempx, tempy = party.Curve.ScalarMult(VssAx[key], VssAy[key], di.Bytes())

		yix, yiy = party.Curve.Add(yix, yiy, tempx, tempy)
		di.Mul(di, party.Rtigi)
		di.Mod(di, party.Curve.Params().N)
	}
	yix, yiy = party.Curve.Add(yix, yiy, Net.Parties[FromNum].Xix, Net.Parties[FromNum].Xiy)

	if !(Yijx.Cmp(yix) == 0 && Yijy.Cmp(yiy) == 0) {
		fmt.Println("error", FromNum)
	}

}

func VssVerify(Net *network.Network, SecertInfo network.MSecretPartiesInfoMap, N int, T int) {
	party := Net.Parties[0]

	for i := 0; i < N; i++ {

		for _, partyi := range Net.Parties {
			//对i发送给j的每一个yij进行验证。

			yij := SecertInfo[Net.Parties[i].ID].Vssy[partyi.ID]
			Yijx, Yijy := party.Curve.ScalarBaseMult(yij.Bytes())

			yix := new(big.Int)
			yiy := new(big.Int)
			di := new(big.Int).Set(partyi.Rtigi)
			tempx := new(big.Int)
			tempy := new(big.Int)

			for key := 1; key < T; key++ {

				tempx, tempy = party.Curve.ScalarMult(SecertInfo[Net.Parties[i].ID].VssAx[key], SecertInfo[Net.Parties[i].ID].VssAy[key], di.Bytes())
				yix, yiy = party.Curve.Add(yix, yiy, tempx, tempy)

				di.Mul(di, partyi.Rtigi)
				di.Mod(di, party.Curve.Params().N)
			}

			yix, yiy = party.Curve.Add(yix, yiy, Net.Parties[i].Xix, Net.Parties[i].Xiy)
			fmt.Println(Yijx.Cmp(yix) == 0 && Yijy.Cmp(yiy) == 0)
		}
	}
}

func VssBack(Net *network.Network, SecertInfo network.MSecretPartiesInfoMap, N int, T int) {
	party := Net.Parties[0]
	for key1 := range SecertInfo {
		Y := new(big.Int)
		for key2 := range SecertInfo {
			Y.Add(Y, SecertInfo[key2].Vssy[key1])
			Y.Mod(Y, party.Curve.Params().N)
		}
		SecertInfo[key1].Y = Y
	}

	for _, val := range Net.Parties {
		lambda := Lagrange(Net, val.ID, T)

		wi := new(big.Int)
		wi.Mul(lambda, SecertInfo[val.ID].Y)
		wi.Mod(wi, party.Curve.Params().N)
		SecertInfo[val.ID].Wi = wi
	}

	A := new(big.Int)
	B := new(big.Int)
	for _, val := range Net.Parties {
		A.Add(A, SecertInfo[val.ID].Xi)
		A.Mod(A, party.Curve.Params().N)
	}
	fmt.Println("A", A)
	for i := 0; i < T; i++ {
		B.Add(B, SecertInfo[Net.Parties[i].ID].Wi)
		B.Mod(B, party.Curve.Params().N)
	}
	fmt.Println("B", B)

}
