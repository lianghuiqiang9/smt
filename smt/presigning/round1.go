package presigning

import (
	"fmt"

	"github.com/lianghuiqiang9/smt/modfiysm2"
	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/vss"
	"github.com/lianghuiqiang9/smt/zk"

	"math/big"
	"sync"

	"github.com/cronokirby/safenum"
	"github.com/lianghuiqiang9/smt/paillier"
	// "github.com/taurusgroup/multi-party-sig/pkg/paillier"
)

type Round1Info struct {
	FromID  string
	FromNum int
	//MtA要发送的消息,Ax,Ay用于验证zk
	Ax *big.Int
	Ay *big.Int
	//Bx,By用于合成R
	Bx *big.Int
	By *big.Int
	//将Gi存储下来，用于后续的MtA
	Gi             *paillier.Ciphertext //ENC(wi)
	Round1logstarp *zk.Logstarp
}

func (p *Round1Info) DoSomething(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {

	//验证zklogstar
	Net.Mtx.Lock()
	flag2 := p.Round1logstarp.LogstarVerify(Net.Hash, Net.Parties[p.FromNum].Curve, Net.Parties[p.FromNum].Aux, Net.Parties[p.FromNum].PaillierPublickey, p.Gi, p.Ax, p.Ay)
	Net.Mtx.Unlock()

	if flag2 != true {
		fmt.Println("error", p.FromID)
	}
	//计算得到Rx，Ry
	party.Rx, party.Ry = party.Curve.Add(party.Rx, party.Ry, p.Bx, p.By)
	//将Gi缓存起来。
	SecretInfo[party.ID].MtAEncW[p.FromID] = p.Gi

}

func Round1(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()
	//生成随机数k，和kG
	ki, _ := modfiysm2.RandFieldElement(party.Curve, nil)
	SecretInfo[party.ID].Ki = ki

	Kix, Kiy := party.Curve.ScalarBaseMult(ki.Bytes())
	SecretInfo[party.ID].Kix, SecretInfo[party.ID].Kiy = Kix, Kiy

	//计算wi
	lambda := vss.Lagrange(Net, party.ID, party.T)
	wi := new(big.Int).Mul(lambda, SecretInfo[party.ID].Y)
	SecretInfo[party.ID].Wi = wi

	Wix, Wiy := party.Curve.ScalarBaseMult(wi.Bytes())
	SecretInfo[party.ID].Wix, SecretInfo[party.ID].Wiy = Wix, Wiy

	//是否需要存储这些数据

	//验证A=sum(lambdai*Yi)
	Wx := new(big.Int)
	Wy := new(big.Int)
	for i := 0; i < party.T; i++ {
		if Net.Parties[i].ID != party.ID {
			lambda := vss.Lagrange(Net, Net.Parties[i].ID, party.T)
			Wix, Wiy := party.Curve.ScalarMult(Net.Parties[i].Yix, Net.Parties[i].Yiy, lambda.Bytes())
			Wx, Wy = party.Curve.Add(Wx, Wy, Wix, Wiy)
		}
	}
	Wx, Wy = party.Curve.Add(Wx, Wy, Wix, Wiy)

	//	fmt.Println("前两个应该都一样，后面也应该都一样", party.ID, party.Ax, party.Ay, Wx, Wy)
	flag := party.Ax.Cmp(Wx) == 0 && party.Ay.Cmp(Wy) == 0
	if flag != true {
		fmt.Println("error,please run presigning checken", party.ID)
	}

	//接下来就是MtA的事情了。当时为什么没有写成函数，这样不是更好调用吗。
	//Wix,Wiy,Kix,Kiy,wi,ki。其中都是他们的椭圆曲线点
	//Ai,Bi,ai,bi
	//最后生成签名的随机点R，和chi=xiki的加共享
	//这里和上面的wix
	x := new(safenum.Int).SetBig(wi, wi.BitLen())
	ct, v := party.PaillierPublickey.Enc(x)
	SecretInfo[party.ID].EncWi = ct
	//生成zkencp
	Net.Mtx.Lock()
	Round1logstarp := zk.LogstarProve(Net.Hash, party.Curve, party.Aux, party.PaillierPublickey, ct, Wix, Wiy, x, v)
	Net.Mtx.Unlock()

	//将Ai,Bi,ct广播出去
	Round1Content := Round1Info{party.ID, party.Num, Wix, Wiy, Kix, Kiy, ct, Round1logstarp}
	Msg := network.Message{FromID: party.ID, ToID: "", MContent: &Round1Content}

	//广播消息,不失去一般性，这里只考虑前T个参与方
	for i := 0; i < party.T; i++ {
		if Net.Parties[i].ID != party.ID {
			Msg.ToID = Net.Parties[i].ID
			Net.Channels[Net.Parties[i].ID] <- &Msg
		}
	}

	//Round1结束

}
