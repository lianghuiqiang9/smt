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
	var net = network.NewNetwork(nil, N, T, C)
	net.Init()
	SecretInfo := make(network.MSecretPartiesInfoMap)
	party := net.Parties[0]

	//random choose Xi, and Rtigi
	for i := 0; i < N; i++ {
		SecretInfoi := new(network.SecretPartyInfo)
		SecretInfoi.Xi, _ = modfiysm2.RandFieldElement(party.Curve, nil)
		SecretInfo[net.Parties[i].ID] = SecretInfoi

		net.Parties[i].Xix, net.Parties[i].Xiy = party.Curve.ScalarBaseMult(SecretInfo[net.Parties[i].ID].Xi.Bytes())
		bf := make([]byte, 16)
		rand.Read(bf)
		net.Parties[i].Rtigi = new(big.Int).SetBytes(bf)
	}
	fmt.Println("init finish")

	VssShare(&net, SecretInfo, N, T)
	VssVerify(&net, SecretInfo, N, T)
	VssBack(&net, SecretInfo, N, T)

	fmt.Println("vss end")

}
