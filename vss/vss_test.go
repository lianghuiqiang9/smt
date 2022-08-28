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

	fmt.Println("测试开始")
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
	party := net.Parties[0]
	//调试的时候初始化

	//随机生成Xi，和Rtigi作为di
	for i := 0; i < N; i++ {
		SecretInfoi := new(network.SecretPartyInfo)
		SecretInfoi.Xi, _ = modfiysm2.RandFieldElement(party.Curve, nil)
		SecretInfo[net.Parties[i].ID] = SecretInfoi

		net.Parties[i].Xix, net.Parties[i].Xiy = party.Curve.ScalarBaseMult(SecretInfo[net.Parties[i].ID].Xi.Bytes())
		bf := make([]byte, 16)
		rand.Read(bf)
		net.Parties[i].Rtigi = new(big.Int).SetBytes(bf)
	}
	fmt.Println("初始化完成")

	Vssshare(&net, SecretInfo, N, T)
	VssVerify(&net, SecretInfo, N, T)
	Vssreshare(&net, SecretInfo, N, T)

	//验证VSS共享是否正确。
	//计算每个人的秘密分享

	fmt.Println("testing end")

}
