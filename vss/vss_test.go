package vss

import (
	"crypto/rand"
	"fmt"

	"github.com/lianghuiqiang9/smt/modfiysm2"
	"github.com/lianghuiqiang9/smt/network"

	"math/big"
	"testing"

	"github.com/tjfoc/gmsm/sm2"
)

func TestVss(t *testing.T) {

	fmt.Println("vss start")

	C := sm2.P256Sm2()
	N := 4
	T := 3
	var Net = network.NewNetwork(nil, N, T, C)
	Net.Init()
	SecretInfo := make(network.MSecretPartiesInfoMap)
	party := Net.Parties[0]

	//random choose Xi, and Rtigi
	for i := 0; i < N; i++ {
		SecretInfoi := new(network.SecretPartyInfo)
		SecretInfoi.Xi, _ = modfiysm2.RandFieldElement(party.Curve, nil)
		SecretInfo[Net.Parties[i].ID] = SecretInfoi

		Net.Parties[i].Xix, Net.Parties[i].Xiy = party.Curve.ScalarBaseMult(SecretInfo[Net.Parties[i].ID].Xi.Bytes())
		bf := make([]byte, 16)
		rand.Read(bf)
		Net.Parties[i].Rtigi = new(big.Int).SetBytes(bf)
	}
	fmt.Println("init finish")

	VssShare(&Net, SecretInfo, N, T)
	VssVerify(&Net, SecretInfo, N, T)
	VssBack(&Net, SecretInfo, N, T)

	fmt.Println("vss end")

}
