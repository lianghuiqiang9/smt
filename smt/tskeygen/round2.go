package tskeygen

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/zk"
)

type Round2Info struct {
	FromID  string
	Xix     *big.Int
	Xiy     *big.Int
	Gammaix *big.Int
	Gammaiy *big.Int
	Rhoi    *big.Int
	Ui      *big.Int
}

// 这里是在第三轮根据Round2Info要做的东西。
func (p *Round2Info) DoSomething(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	Net.Mtx.Lock()
	Net.Hash.Write(zk.BytesCombine(party.Rtig.Bytes(), p.Xix.Bytes(), p.Xiy.Bytes(), p.Gammaix.Bytes(), p.Gammaiy.Bytes(), p.Rhoi.Bytes(), p.Ui.Bytes()))
	bytes := Net.Hash.Sum(nil)
	//计算hash承诺
	Vi2 := new(big.Int).SetBytes(bytes)
	Net.Hash.Reset()
	Net.Mtx.Unlock()
	//比较Vi2和Vi
	Vi3 := SecretInfo[party.ID].V[p.FromID]

	if Vi2.Cmp(Vi3) != 0 {
		fmt.Println("error", p.FromID)
	}
	//将Rhoi相加
	party.Rho.Add(party.Rho, p.Rhoi)

}

// 这是第二轮要做的消息。
func Round2(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()

	Vmap := make(map[string]*big.Int)
	SecretInfo[party.ID].V = Vmap

	for i := 0; i < party.N-1; i++ {
		val := <-Net.Channels[party.ID] // 出 chan
		val.MContent.DoSomething(party, Net, SecretInfo)
	}

	MRoundContent := Round2Info{party.ID, SecretInfo[party.ID].Xix, SecretInfo[party.ID].Xiy, SecretInfo[party.ID].Gammaix, SecretInfo[party.ID].Gammaiy, SecretInfo[party.ID].Rhoi, SecretInfo[party.ID].Ui}

	Msg := network.Message{FromID: party.ID, ToID: "", MContent: &MRoundContent}

	//广播消息
	for _, mparty := range Net.Parties {
		//本地计算消息位置2，向每一个参与方广播不同消息使用
		if mparty.ID != party.ID {
			Msg.ToID = mparty.ID
			Net.Channels[mparty.ID] <- &Msg
		}

	}

}
