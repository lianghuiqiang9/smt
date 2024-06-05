package tskeygen

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/lianghuiqiang9/smt/network"
)

func Output(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()

	Delta := new(big.Int).Set(SecretInfo[party.ID].Deltai)
	party.Delta = Delta

	Deltax := new(big.Int).Set(SecretInfo[party.ID].Deltaix)
	Deltay := new(big.Int).Set(SecretInfo[party.ID].Deltaiy)
	party.Deltax, party.Deltay = Deltax, Deltay

	for i := 0; i < party.N-1; i++ {
		val := <-Net.Channels[party.ID]
		val.MContent.DoSomething(party, Net, SecretInfo)

	}
	Dx, Dy := party.Curve.ScalarBaseMult(party.Delta.Bytes())
	flag := Dx.Cmp(party.Deltax) == 0 && Dy.Cmp(party.Deltay) == 0
	if !flag {
		fmt.Println("error")
	}
	//计算 X = delta^-1 Gamma - G
	party.Delta.ModInverse(party.Delta, party.Curve.Params().N)

	party.Xx, party.Xy = party.Curve.ScalarMult(party.Gammax, party.Gammay, party.Delta.Bytes())
	var One = new(big.Int).SetInt64(1)
	OneNeg := new(big.Int).Sub(party.Curve.Params().N, One)

	NegGx, NegGy := party.Curve.ScalarBaseMult(OneNeg.Bytes())
	party.Xx, party.Xy = party.Curve.Add(party.Xx, party.Xy, NegGx, NegGy)

}
