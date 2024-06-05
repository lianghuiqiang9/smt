package smt

import (
	"fmt"
	"testing"
	"time"

	"github.com/lianghuiqiang9/smt/modfiysm2"
	"github.com/lianghuiqiang9/smt/network"

	"github.com/tjfoc/gmsm/sm2"
)

func TestSmt(t *testing.T) {

	C := sm2.P256Sm2()
	N := 4
	T := 3
	var Net = network.NewNetwork(nil, N, T, C)
	Net.Init()
	SecretInfo := make(network.MSecretPartiesInfoMap)

	//paillierkeygen generates appropriate paillier public and private keys, persedern numbers, and Rtig for each party.
	fmt.Println("paillierkeygen")
	Paillierkeygen(&Net, SecretInfo)

	//tskeygen generates the private keys xi, yi, and public keys x^-1-1G for each participant.
	fmt.Println("tskeygen")
	Tskeygen(&Net, SecretInfo)

	//presigning, T players are required to negotiate random numbers.
	fmt.Println("presigning")

	Presigning(&Net, SecretInfo)

	msg := []byte("HELLO MSM2")
	Net.Msg = msg

	fmt.Println("signing")
	start := time.Now()
	Signing(&Net, SecretInfo)

	cost := time.Since(start)
	fmt.Println("signing cost=", cost.Seconds())
	party0 := Net.Parties[0]

	Z := modfiysm2.ComputeZ(Net.Hash, party0.Rtig, party0.Rho, party0.Xx, party0.Xy)

	msg2 := []byte("HELLO MSM2")
	flag := modfiysm2.Verify(C, Net.Hash, msg2, Z, party0.Xx, party0.Xy, party0.R, party0.S)
	fmt.Println("verfication result", flag)

}

func BenchmarkSmt(b *testing.B) {

	for i := 0; i < b.N; i++ {
		C := sm2.P256Sm2()
		N := 4
		T := 3
		var Net = network.NewNetwork(nil, N, T, C)
		Net.Init()
		SecretInfo := make(network.MSecretPartiesInfoMap)

		Paillierkeygen(&Net, SecretInfo)
		Tskeygen(&Net, SecretInfo)

		Presigning(&Net, SecretInfo)

		msg := []byte("HELLO MSM2")
		Net.Msg = msg
		Signing(&Net, SecretInfo)

		party0 := Net.Parties[0]

		Z := modfiysm2.ComputeZ(Net.Hash, party0.Rtig, party0.Rho, party0.Xx, party0.Xy)

		msg2 := []byte("HELLO MSM2")
		flag := modfiysm2.Verify(C, Net.Hash, msg2, Z, party0.Xx, party0.Xy, party0.R, party0.S)
		fmt.Println("verfication result", flag)
	}
}
