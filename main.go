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

	start1 := time.Now()

	//选定初始化曲线
	C := sm2.P256Sm2()
	//确定参与方人数N<26
	N := 9
	//确定阈值T<=N
	T := 9
	//建立network
	var net = network.NewNetwork(nil, N, T, C)
	//初始化通信信道
	net.Init()
	//初始化秘密信息map，每个参与方只使用自己的的。
	SecretInfo := make(network.MSecretPartiesInfoMap)

	//paillierkeygen为每一方生成合适的paillier公私钥，persedern数，和Rtig
	fmt.Println("paillierkeygen")
	smt.Paillierkeygen(&net, SecretInfo)
	cost1 := time.Since(start1)
	fmt.Println("paillierkeygen cost=", cost1.Seconds())

	fmt.Println("k", C.Params().N.BitLen(), "mu", net.Parties[0].PaillierPublickey.N().BitLen())

	//tskeygen为每一个参与方生成私钥xi,yi,和公钥x^-1-1G。
	fmt.Println("tskeygen")

	start2 := time.Now()
	smt.Tskeygen(&net, SecretInfo)

	cost2 := time.Since(start2)
	fmt.Println("tskeygen cost=", cost2.Seconds())

	fmt.Println("tskeygen end")
	start3 := time.Now()
	smt.Presigning(&net, SecretInfo)

	cost3 := time.Since(start3)
	fmt.Println("presigning cost=", cost3.Seconds())

	msg := []byte("HELLO MSM2")
	net.Msg = msg

	start4 := time.Now()
	smt.Signing(&net, SecretInfo)
	cost4 := time.Since(start4)

	fmt.Println("signing cost=", cost4.Microseconds())
	R := new(big.Int).Set(net.Parties[0].R)
	S := new(big.Int).Set(net.Parties[0].S)
	party := net.Parties[0]

	Z := modfiysm2.ComputeZ(net.Hash, &party)
	flag := modfiysm2.Verify(C, net.Hash, msg, Z, party.Xx, party.Xy, R, S)
	fmt.Println("签名验证结果", flag)

	fmt.Println("main end")

}

/*
	//验证签名次数为M个
	SignNum := 1
	MSignInfo := make([]smt.SignInfo, SignNum)
	party := net.Parties[0]

	start := time.Now()
	for i := 0; i < SignNum; i++ {
		smt.Presigning(&net, SecretInfo)
		msg := []byte("HELLO MSM2")
		net.Msg = msg
		smt.Signing(&net, SecretInfo)
		R := new(big.Int).Set(net.Parties[0].R)
		S := new(big.Int).Set(net.Parties[0].S)
		MSignInfo[i] = smt.SignInfo{Msg: msg, R: R, S: S}
	}

	cost := time.Since(start)
	fmt.Println("测试次数", SignNum, "cost=", cost.Seconds(), "平均时间", cost.Seconds()/float64(SignNum))

	Z := modfiysm2.ComputeZ(net.Hash, &party)

	fmt.Println("Z", Z)

	for i := 0; i < SignNum; i++ {
		flag := modfiysm2.Verify(C, net.Hash, MSignInfo[i].Msg, Z, party.Xx, party.Xy, MSignInfo[i].R, MSignInfo[i].S)
		fmt.Println("第", i, "次签名验证结果", flag)
	}
*/
