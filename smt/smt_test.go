package smt

import (
	"fmt"
	"testing"
	"time"

	"github.com/lianghuiqiang9/smt/modfiysm2"
	"github.com/lianghuiqiang9/smt/network"

	"github.com/tjfoc/gmsm/sm2"
)

//var Net1 Network.Network
//var SecretInfo1 Network.MSecretPartiesInfoMap

func TestSmt(t *testing.T) {

	C := sm2.P256Sm2()
	N := 4
	T := 3
	var Net = network.NewNetwork(nil, N, T, C)
	Net.Init()
	SecretInfo := make(network.MSecretPartiesInfoMap)

	//paillierkeygen为每一方生成合适的paillier公私钥，persedern数，和Rtig
	fmt.Println("paillierkeygen")
	Paillierkeygen(&Net, SecretInfo)

	//tskeygen为每一个参与方生成私钥xi,yi,和公钥x^-1-1G。
	fmt.Println("tskeygen")
	Tskeygen(&Net, SecretInfo)

	//presigning, 需要T个参与方, 协商随机数
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
		fmt.Println("签名验证结果", flag)
	}
}
