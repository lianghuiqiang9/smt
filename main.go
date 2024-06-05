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

	//选定初始化曲线
	C := sm2.P256Sm2()
	//确定参与方人数N<26
	N := 3
	//确定阈值T<=N
	T := 3
	//建立network
	var net = network.NewNetwork(nil, N, T, C)
	//初始化通信信道
	net.Init()
	//初始化秘密信息map。
	SecretInfo := make(network.MSecretPartiesInfoMap)

	//paillierkeygen为每一方生成合适的paillier公私钥，persedern数，和Rtig
	fmt.Println("paillierkeygen")
	smt.Paillierkeygen(&net, SecretInfo)
	cost := time.Since(start)
	fmt.Println("paillierkeygen cost=", cost.Seconds())

	fmt.Println("k", C.Params().N.BitLen(), "mu", net.Parties[0].PaillierPublickey.N().BitLen())

	//tskeygen为每一个参与方生成私钥xi,yi,和公钥x^-1-1G。
	fmt.Println("tskeygen")

	start = time.Now()
	smt.Tskeygen(&net, SecretInfo)

	cost = time.Since(start)
	fmt.Println("tskeygen cost=", cost.Seconds())

	fmt.Println("presigning")
	start = time.Now()
	smt.Presigning(&net, SecretInfo)

	cost = time.Since(start)
	fmt.Println("presigning cost=", cost.Seconds())

	Msg := []byte("HELLO MSM2")
	net.Msg = Msg

	fmt.Println("signing")
	start = time.Now()
	smt.Signing(&net, SecretInfo)
	cost = time.Since(start)

	fmt.Println("signing cost=", cost.Seconds())
	R := new(big.Int).Set(net.Parties[0].R)
	S := new(big.Int).Set(net.Parties[0].S)
	party0 := net.Parties[0]

	Z := modfiysm2.ComputeZ(net.Hash, party0.Rtig, party0.Rho, party0.Xx, party0.Xy)
	flag := modfiysm2.Verify(C, net.Hash, Msg, Z, party0.Xx, party0.Xy, R, S)
	fmt.Println("verfication result : ", flag)

}
