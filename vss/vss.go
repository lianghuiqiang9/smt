package vss

import (
	"fmt"
	"math/big"

	"github.com/lianghuiqiang9/smt/modfiysm2"
	"github.com/lianghuiqiang9/smt/network"

	"github.com/cronokirby/safenum"
	// "github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/lianghuiqiang9/smt/paillier"
)

// 不失去一般性，我们取签名方为第0方到第T-1方。如需拓展，还需要结合签名方，来计算对应的lagrange系数
// id属于0到T-1。
func Lagrange(net *network.Network, id string, T int) *big.Int {
	N := net.Parties[0].Curve.Params().N
	//找到id的di，和所在位置i
	i := 0
	xi := new(big.Int)
	for key, partyi := range net.Parties {
		if partyi.ID == id {
			xi = partyi.Rtigi
			i = key
		}
	}

	//	fmt.Println(id, "xi,i", xi, i)
	//计算系数
	xj := new(big.Int)
	A, _ := new(big.Int).SetString("1", 0)
	B, _ := new(big.Int).SetString("1", 0)
	//这里总是假设去前T个吧。
	for key := 0; key < T; key++ {
		if key != i {
			//计算每一项
			xj = xj.Neg(net.Parties[key].Rtigi)
			//			fmt.Println(id, xj)
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

func Vssshare1(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	//新建一些VSS信息
	Vssa := make(map[int]*big.Int)
	VssAx := make(map[int]*big.Int)
	VssAy := make(map[int]*big.Int)
	for i := 1; i < party.T; i++ {
		Vssa[i], _ = modfiysm2.RandFieldElement(party.Curve, nil)
		VssAx[i], VssAy[i] = party.Curve.ScalarBaseMult(Vssa[i].Bytes())
	}
	//	fmt.Println("初始化VSSshare成功")

	//计算分享值,显然，这里需要对每一个party计算一个，每一次计算有一个T循环，所以有两层循环
	Vssy := make(map[string]*big.Int)
	VssEncy := make(map[string]*paillier.Ciphertext)
	for _, partyi := range net.Parties {

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

		CC := new(safenum.Int).SetBig(yi, yi.BitLen())

		ct2, _ := partyi.PaillierPublickey.Enc(CC)
		VssEncy[partyi.ID] = ct2

	}

	SecretInfo[party.ID].Vssa = Vssa
	SecretInfo[party.ID].VssAx = VssAx
	SecretInfo[party.ID].VssAy = VssAy
	SecretInfo[party.ID].Vssy = Vssy
	SecretInfo[party.ID].VssEncy = VssEncy

}

func Vssshare(net *network.Network, SecertInfo network.MSecretPartiesInfoMap, N int, T int) {

	party := net.Parties[0]
	for i := 0; i < N; i++ {

		//新建一些VSS信息
		Vssa := make(map[int]*big.Int)
		VssAx := make(map[int]*big.Int)
		VssAy := make(map[int]*big.Int)

		//初始化VSS秘密值
		for i := 1; i < party.T; i++ {
			Vssa[i], _ = modfiysm2.RandFieldElement(party.Curve, nil)

			VssAx[i], VssAy[i] = party.Curve.ScalarBaseMult(Vssa[i].Bytes())
		}

		//计算分享值
		Vssy := make(map[string]*big.Int)

		for _, partyi := range net.Parties {

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

			yi.Add(yi, SecertInfo[net.Parties[i].ID].Xi)
			yi.Mod(yi, party.Curve.Params().N)

			Vssy[partyi.ID] = yi

		}

		SecertInfo[net.Parties[i].ID].Vssa = Vssa
		SecertInfo[net.Parties[i].ID].VssAx = VssAx
		SecertInfo[net.Parties[i].ID].VssAy = VssAy
		SecertInfo[net.Parties[i].ID].Vssy = Vssy
	}
}

func VssVerify1(FromNum int, yij *big.Int, VssAx map[int]*big.Int, VssAy map[int]*big.Int, party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {

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
	yix, yiy = party.Curve.Add(yix, yiy, net.Parties[FromNum].Xix, net.Parties[FromNum].Xiy)

	if (Yijx.Cmp(yix) == 0 && Yijy.Cmp(yiy) == 0) != true {
		fmt.Println("error", FromNum)
	}

}

func VssVerify(net *network.Network, SecertInfo network.MSecretPartiesInfoMap, N int, T int) {
	party := net.Parties[0]

	for i := 0; i < N; i++ {

		for _, partyi := range net.Parties {
			//对i发送给j的每一个yij进行验证。

			yij := SecertInfo[net.Parties[i].ID].Vssy[partyi.ID]
			Yijx, Yijy := party.Curve.ScalarBaseMult(yij.Bytes())

			yix := new(big.Int)
			yiy := new(big.Int)
			di := new(big.Int).Set(partyi.Rtigi)
			tempx := new(big.Int)
			tempy := new(big.Int)

			for key := 1; key < T; key++ {

				tempx, tempy = party.Curve.ScalarMult(SecertInfo[net.Parties[i].ID].VssAx[key], SecertInfo[net.Parties[i].ID].VssAy[key], di.Bytes())

				yix, yiy = party.Curve.Add(yix, yiy, tempx, tempy)

				di.Mul(di, partyi.Rtigi)
				di.Mod(di, party.Curve.Params().N)
			}

			yix, yiy = party.Curve.Add(yix, yiy, net.Parties[i].Xix, net.Parties[i].Xiy)
			fmt.Println(Yijx.Cmp(yix) == 0 && Yijy.Cmp(yiy) == 0)
		}
	}
}

func Vssreshare(net *network.Network, SecertInfo network.MSecretPartiesInfoMap, N int, T int) {
	party := net.Parties[0]
	for key1 := range SecertInfo {
		Y := new(big.Int)
		for key2 := range SecertInfo {
			Y.Add(Y, SecertInfo[key2].Vssy[key1])
			Y.Mod(Y, party.Curve.Params().N)
		}
		SecertInfo[key1].Y = Y
	}

	//构造拉格朗日算子，先写简单的前3个的，其后面的一致的。

	for _, val := range net.Parties {
		lambda := Lagrange(net, val.ID, T)

		wi := new(big.Int)
		wi.Mul(lambda, SecertInfo[val.ID].Y)
		wi.Mod(wi, party.Curve.Params().N)
		SecertInfo[val.ID].Wi = wi
	}

	A := new(big.Int)
	B := new(big.Int)
	for _, val := range net.Parties {
		A.Add(A, SecertInfo[val.ID].Xi)
		A.Mod(A, party.Curve.Params().N)
	}
	fmt.Println("A", A)
	//唉，T+1呀，宝贝
	for i := 0; i < T; i++ {
		B.Add(B, SecertInfo[net.Parties[i].ID].Wi)
		B.Mod(B, party.Curve.Params().N)
	}
	fmt.Println("B", B)

}

//验证VSS共享是否正确。
//计算每个人的秘密分享
/*
	fmt.Println("对修改小数")
	net.Parties[0].Rtigi, _ = new(big.Int).SetString("1", 0)
	net.Parties[1].Rtigi, _ = new(big.Int).SetString("2", 0)
	net.Parties[2].Rtigi, _ = new(big.Int).SetString("3", 0)
	net.Parties[3].Rtigi, _ = new(big.Int).SetString("4", 0)
	fmt.Println(net.Parties[0].Rtigi)

	SecertInfo["a"].X, _ = new(big.Int).SetString("5", 0)
	SecertInfo["b"].X, _ = new(big.Int).SetString("6", 0)
	SecertInfo["c"].X, _ = new(big.Int).SetString("7", 0)
	SecertInfo["d"].X, _ = new(big.Int).SetString("8", 0)
	fmt.Println(SecertInfo["a"].X)
	fmt.Println(SecertInfo["b"].X)
	fmt.Println(SecertInfo["c"].X)
	fmt.Println(SecertInfo["d"].X)
	SecertInfo["a"].Vssa[1], _ = new(big.Int).SetString("3", 0)
	SecertInfo["a"].Vssa[2], _ = new(big.Int).SetString("7", 0)
	SecertInfo["b"].Vssa[1], _ = new(big.Int).SetString("2", 0)
	SecertInfo["b"].Vssa[2], _ = new(big.Int).SetString("4", 0)
	SecertInfo["c"].Vssa[1], _ = new(big.Int).SetString("1", 0)
	SecertInfo["c"].Vssa[2], _ = new(big.Int).SetString("1", 0)
	SecertInfo["d"].Vssa[1], _ = new(big.Int).SetString("2", 0)
	SecertInfo["d"].Vssa[2], _ = new(big.Int).SetString("2", 0)
	fmt.Println(SecertInfo["a"].Vssa)
	fmt.Println(SecertInfo["b"].Vssa)
	fmt.Println(SecertInfo["c"].Vssa)
	fmt.Println(SecertInfo["d"].Vssa)
	SecertInfo["a"].Y, _ = new(big.Int).SetString("9", 0)
	SecertInfo["b"].Y, _ = new(big.Int).SetString("7", 0)
	SecertInfo["c"].Y, _ = new(big.Int).SetString("7", 0)
	SecertInfo["d"].Y, _ = new(big.Int).SetString("9", 0)
*/
