package round

import (
	"fmt"
	"sync"

	"github.com/lianghuiqiang9/smt/network"
)

type StartRoundContent struct {
	MRoundNumber int
	Minfo        int
	Num          int
}

func (p *StartRoundContent) DoSomething(party *network.Party, net *network.Network, SecertInfo network.MSecretPartiesInfoMap) {
	fmt.Println("this is the Round number ", p.MRoundNumber)
}

func StartRound(party *network.Party, Net *network.Network, SecertInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()

	MStartRoundContent := StartRoundContent{0, 1, 1}

	//本地计算消息位置1，向每一个参与方广播相同消息的时候使用
	Msg := network.Message{FromID: "a", ToID: "", MContent: &MStartRoundContent}

	//广播消息
	for _, mparty := range Net.Parties {
		//本地计算消息位置2，向每一个参与方广播不同消息使用
		if mparty.ID != party.ID {
			Net.Channels[mparty.ID] <- &Msg
		}
	}
}
