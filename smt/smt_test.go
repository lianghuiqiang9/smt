package smt

import (
	"fmt"
	"testing"
	"time"

	"github.com/lianghuiqiang9/smt/modfiysm2"
	"github.com/lianghuiqiang9/smt/network"

	"github.com/tjfoc/gmsm/sm2"
)

var net1 network.Network
var SecretInfo1 network.MSecretPartiesInfoMap

func TestSmt(t *testing.T) {

	//选定初始化曲线
	C := sm2.P256Sm2()
	//确定参与方人数N<26
	N := 4
	//确定阈值T<=N
	T := 3
	//建立network
	var net = network.NewNetwork(nil, N, T, C)
	//初始化通信信道
	net.Init()
	//初始化秘密信息map，每个参与方只使用自己的的。
	SecretInfo := make(network.MSecretPartiesInfoMap)

	//paillierkeygen为每一方生成合适的paillier公私钥，persedern数，和Rtig
	fmt.Println("paillierkeygen")
	Paillierkeygen(&net, SecretInfo)

	//tskeygen为每一个参与方生成私钥xi,yi,和公钥x^-1-1G。
	fmt.Println("tskeygen")
	Tskeygen(&net, SecretInfo)
	fmt.Println("tskeygen end")

	//运行到presigning了，就需要T个参与方就可以了。协商随机数
	fmt.Println("presigning")

	//	start := time.Now()
	Presigning(&net, SecretInfo)

	msg := []byte("HELLO MSM2")
	net.Msg = msg

	fmt.Println("signing")
	start2 := time.Now()
	Signing(&net, SecretInfo)

	cost2 := time.Since(start2)
	fmt.Println("signing cost=", cost2.Seconds())
	party := net.Parties[0]

	Z := modfiysm2.ComputeZ(net.Hash, &party)

	msg2 := []byte("HELLO MSM2")
	flag := modfiysm2.Verify(C, net.Hash, msg2, Z, party.Xx, party.Xy, party.R, party.S)
	fmt.Println("签名验证结果", flag)

	fmt.Println("testing end")

}

func BenchmarkSmt(b *testing.B) {

	for i := 0; i < b.N; i++ {
		//选定初始化曲线
		C := sm2.P256Sm2()
		//确定参与方人数N<26
		N := 4
		//确定阈值T<=N
		T := 3
		//建立network
		var net = network.NewNetwork(nil, N, T, C)
		//初始化通信信道
		net.Init()
		//初始化秘密信息map，每个参与方只使用自己的的。
		SecretInfo := make(network.MSecretPartiesInfoMap)

		Paillierkeygen(&net, SecretInfo)
		Tskeygen(&net, SecretInfo)

		Presigning(&net, SecretInfo)

		msg := []byte("HELLO MSM2")
		net.Msg = msg
		Signing(&net, SecretInfo)

		party := net.Parties[0]

		Z := modfiysm2.ComputeZ(net.Hash, &party)

		msg2 := []byte("HELLO MSM2")
		flag := modfiysm2.Verify(C, net.Hash, msg2, Z, party.Xx, party.Xy, party.R, party.S)
		fmt.Println("签名验证结果", flag)
	}
}
