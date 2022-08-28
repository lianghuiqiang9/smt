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

// 这里是第三轮要做的东西了吧。
func (p *Round2Info) DoSomething(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	//注意，落到这里的时候，已经是每一个消息，每一个party了
	net.Mtx.Lock()
	net.Hash.Write(zk.BytesCombine(party.Rtig.Bytes(), p.Xix.Bytes(), p.Xiy.Bytes(), p.Gammaix.Bytes(), p.Gammaiy.Bytes(), p.Rhoi.Bytes(), p.Ui.Bytes()))
	bytes := net.Hash.Sum(nil)
	//计算hash承诺
	Vi2 := new(big.Int).SetBytes(bytes)

	net.Hash.Reset()
	net.Mtx.Unlock()
	//比较Vi2和Vi
	Vi3 := SecretInfo[party.ID].V[p.FromID]

	//	fmt.Println("Vi3", party.ID, p.FromID, Vi3)
	if Vi2.Cmp(Vi3) != 0 {
		fmt.Println("error", p.FromID)
	}
	//将Rhoi加在一块
	party.Rho.Add(party.Rho, p.Rhoi)

}

// 这是第二轮要做的消息了。
func Round2(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()

	//需要先make一个map，然后才能赋值。
	Vmap := make(map[string]*big.Int)
	SecretInfo[party.ID].V = Vmap

	//本地接受消息
	for i := 0; i < party.N-1; i++ {
		val := <-net.Channels[party.ID] // 出 chan
		//记录了每一个参与方的Vi
		val.MContent.DoSomething(party, net, SecretInfo)
		//本地计算消息
	}

	MRoundContent := Round2Info{party.ID, SecretInfo[party.ID].Xix, SecretInfo[party.ID].Xiy, SecretInfo[party.ID].Gammaix, SecretInfo[party.ID].Gammaiy, SecretInfo[party.ID].Rhoi, SecretInfo[party.ID].Ui}
	//本地计算消息位置1，向每一个参与方广播相同消息的时候使用
	Msg := network.Message{FromID: party.ID, ToID: "", MContent: &MRoundContent}

	//广播消息
	for _, mparty := range net.Parties {
		//本地计算消息位置2，向每一个参与方广播不同消息使用

		//这里也是单独的情况下

		if mparty.ID != party.ID {
			Msg.ToID = mparty.ID
			net.Channels[mparty.ID] <- &Msg
		}

	}

}
