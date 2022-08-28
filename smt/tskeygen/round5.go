package tskeygen

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/zk"
)

type Round5Info struct {
	FromID  string
	FromNum int
	Deltaix *big.Int
	Deltaiy *big.Int
	logp1   *zk.Logp
	logp2   *zk.Logp
	Deltai  *big.Int
}

func (p *Round5Info) DoSomething(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	//接下来就要验证Output的一些信息，是否计算准确了。肯定又是一个大难关呀。加油吧。
	//验证两个zk
	net.Mtx.Lock()
	flag := p.logp1.LogVerify(net.Hash, net.Parties[p.FromNum].Curve, net.Parties[p.FromNum].Yix, net.Parties[p.FromNum].Yiy)
	flag1 := p.logp2.LogVerify1(net.Hash, net.Parties[p.FromNum].Curve, p.Deltaix, p.Deltaiy, net.Parties[p.FromNum].Gammax, net.Parties[p.FromNum].Gammay)
	net.Mtx.Unlock()
	if flag != true {
		fmt.Println("error", p.FromID)
	}
	if flag1 != true {
		fmt.Println("error", p.FromID)
	}
	//计算Delta，验证Delta
	party.Delta = party.Delta.Add(party.Delta, p.Deltai)
	party.Delta = party.Delta.Mod(party.Delta, party.Curve.Params().N)
	party.Deltax, party.Deltay = party.Curve.Add(party.Deltax, party.Deltay, p.Deltaix, p.Deltaiy)
}

func Round5(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()
	//得，又是写了一个下午，发现是一个错误的情况。代码太长久会出现各种各样的问题。
	aibi := new(big.Int).Mul(SecretInfo[party.ID].Xi, SecretInfo[party.ID].Gammai)
	aibi = aibi.Mod(aibi, party.Curve.Params().N)
	SecretInfo[party.ID].Deltai = aibi

	for i := 0; i < party.N-1; i++ {
		val := <-net.Channels[party.ID] // 出 chan
		val.MContent.DoSomething(party, net, SecretInfo)
	}

	//送过去两个zk，还有Delta。然后就是output了。就回到最后的验证步骤了。如果验证正确了。那么那么。我们就结束了这个鬼东西了。
	Deltaix, Deltaiy := party.Curve.ScalarMult(party.Gammax, party.Gammay, SecretInfo[party.ID].Xi.Bytes())
	Deltaxx := new(big.Int).Set(Deltaix)
	Deltayy := new(big.Int).Set(Deltaiy)
	SecretInfo[party.ID].Deltaix, SecretInfo[party.ID].Deltaiy = Deltaxx, Deltayy

	net.Mtx.Lock()
	logp1 := zk.LogProve(net.Hash, party.Curve, party.Yix, party.Yiy, SecretInfo[party.ID].Y)
	logp2 := zk.LogProve1(net.Hash, party.Curve, Deltaix, Deltaiy, party.Gammax, party.Gammay, SecretInfo[party.ID].Xi)
	net.Mtx.Unlock()
	//广播消息位置1
	Deltai := new(big.Int).Set(SecretInfo[party.ID].Deltai)

	MRoundContent := Round5Info{party.ID, party.Num, Deltaix, Deltaiy, logp1, logp2, Deltai}
	//本地计算消息位置1，向每一个参与方广播相同消息的时候使用
	Msg := network.Message{FromID: party.ID, ToID: "", MContent: &MRoundContent}

	for _, mparty := range net.Parties {
		if mparty.ID != party.ID {
			Msg.ToID = mparty.ID
			net.Channels[mparty.ID] <- &Msg
		}

	}

}
