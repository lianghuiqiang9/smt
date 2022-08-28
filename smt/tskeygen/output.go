package tskeygen

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/lianghuiqiang9/smt/network"
)

func Output(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()

	Delta := new(big.Int).Set(SecretInfo[party.ID].Deltai)
	party.Delta = Delta

	Deltax := new(big.Int).Set(SecretInfo[party.ID].Deltaix)
	Deltay := new(big.Int).Set(SecretInfo[party.ID].Deltaiy)
	party.Deltax, party.Deltay = Deltax, Deltay

	for i := 0; i < party.N-1; i++ {
		val := <-net.Channels[party.ID] // 出 chan
		val.MContent.DoSomething(party, net, SecretInfo)
		//本地计算消息
	}
	Dx, Dy := party.Curve.ScalarBaseMult(party.Delta.Bytes())
	flag := Dx.Cmp(party.Deltax) == 0 && Dy.Cmp(party.Deltay) == 0
	if flag != true {
		fmt.Println("error")
	}
	//计算X=delta^-1Gamma-G
	//delta为party.Delta
	//gamma为party.Gammax,party.Gammay.

	//不要忘记求逆呀。
	party.Delta.ModInverse(party.Delta, party.Curve.Params().N)

	party.Xx, party.Xy = party.Curve.ScalarMult(party.Gammax, party.Gammay, party.Delta.Bytes())
	var one = new(big.Int).SetInt64(1) //将1变成大数
	oneNeg := new(big.Int).Sub(party.Curve.Params().N, one)

	NegGx, NegGy := party.Curve.ScalarBaseMult(oneNeg.Bytes())
	party.Xx, party.Xy = party.Curve.Add(party.Xx, party.Xy, NegGx, NegGy)

	//	fmt.Println(party.ID, party.Xx, party.Xy)

}
