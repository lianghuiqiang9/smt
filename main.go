package main

import (
	"fmt"
	"math/big"
	"time"

	"github.com/lianghuiqiang9/smt/modfiysm2"
	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/smt"

	"github.com/tjfoc/gmsm/sm2"
)

func main() {

	start := time.Now()

	//init curve
	C := sm2.P256Sm2()
	//N<26
	N := 3
	//T<=N
	T := 3
	//init network
	var Net = network.NewNetwork(nil, N, T, C)
	Net.Init()
	//init secert info.
	SecretInfo := make(network.MSecretPartiesInfoMap)

	//paillierkeygen generate the paillier pk and sk, persedern number, and Rtig
	fmt.Println("paillierkeygen")
	smt.Paillierkeygen(&Net, SecretInfo)
	cost := time.Since(start)
	fmt.Println("paillierkeygen cost : ", cost.Seconds(), "s")

	fmt.Println("k", C.Params().N.BitLen(), "mu", Net.Parties[0].PaillierPublickey.N().BitLen())

	//tskeygen generate the sm2 xi, yi, and pk = x^-1-1G。
	fmt.Println("tskeygen")

	start = time.Now()
	smt.Tskeygen(&Net, SecretInfo)

	cost = time.Since(start)
	fmt.Println("tskeygen cost       : ", cost.Seconds(), "s")

	fmt.Println("presigning")
	start = time.Now()
	smt.Presigning(&Net, SecretInfo)

	cost = time.Since(start)
	fmt.Println("presigning cost     : ", cost.Seconds(), "s")

	Msg := []byte("HELLO MSM2")
	Net.Msg = Msg

	fmt.Println("signing")
	start = time.Now()
	smt.Signing(&Net, SecretInfo)
	cost = time.Since(start)

	fmt.Println("signing cost        : ", cost.Seconds(), "s")
	R := new(big.Int).Set(Net.Parties[0].R)
	S := new(big.Int).Set(Net.Parties[0].S)
	party0 := Net.Parties[0]

	MsgTemp := []byte("HELLO MSM2")
	Z := modfiysm2.ComputeZ(Net.Hash, party0.Rtig, party0.Rho, party0.Xx, party0.Xy)
	flag := modfiysm2.Verify(C, Net.Hash, MsgTemp, Z, party0.Xx, party0.Xy, R, S)
	fmt.Println("verfication result  : ", flag)

}
