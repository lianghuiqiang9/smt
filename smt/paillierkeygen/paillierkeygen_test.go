package paillierkeygen

//network 统一管理所有的公开信息。
//每一个party，应该有一个指针，指向自己的私有信息。

//公有信息包括
/*初始信息
N                     party人数
T                     阈值
Curve                 椭圆曲线的参数，
ID                    自己的唯一的ID标识符

PaillierKeyGen结束后的信息
Rtig                  本次签名的会话标识符
PaillierPublicKey     应该说是paillier的公钥
Aux                   pederson信息。

SM2TsKeyGen结束后的信息
X                     主公钥x^-1-1G
Xi                    小公钥xiG
Yi                    VSS分享后的小公钥sum(lambdai*Yi)=xG=A
A                     小公钥xG
PreSigning结束后的信息
R                     用于签名的随机数
Signing输入msg,待签名消息
r                     签名信息r
s                     签名信息s

*/
//私有信息
/*
PaillierKeyGen结束后的信息

PaillierSecertKey     paillier的私钥

SM2TsKeyGen结束后的信息
x                     小私钥sum(x)G=xG
y                     小私钥sum(lambdai*yi)G=xG
PreSigning结束后的信息(前面都是n个人，现在变成了t个人了)
w                     小私钥lambdai*yi
chi                   随机消息和私钥的sum(chi)=xk
Signing输入msg,待签名消息
清空w,chi


*/

import (
	"fmt"
	"testing"

	"github.com/lianghuiqiang9/smt/network"

	"github.com/lianghuiqiang9/smt/round"

	"github.com/tjfoc/gmsm/sm2"
)

func TestPaillierKeyGen(t *testing.T) {
	C := sm2.P256Sm2()
	N := 4
	T := 3
	var Net = network.NewNetwork(nil, N, T, C)
	Net.Init()

	fmt.Println(Net.Parties, Net.Channels, Net.Hash)

	SecertInfo := make(network.MSecretPartiesInfoMap)

	round.MRound(Round1, &Net, SecertInfo)
	fmt.Println(Net.Parties, Net.Channels, Net.Hash)

	round.MRound(Output, &Net, SecertInfo)

	fmt.Println(Net.Parties, Net.Channels, Net.Hash)

	fmt.Println("main end")

}
