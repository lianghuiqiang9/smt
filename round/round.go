package round

import (
	"fmt"
	"sync"

	"github.com/lianghuiqiang9/smt/network"
)

type RoundContent struct {
	MRoundNumber int
	Minfo        int
	Num          int
}

func Round(party *network.Party, Net *network.Network, SecertInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()
	for i := 0; i < party.N-1; i++ {
		val := <-Net.Channels[party.ID] // 出 chan
		fmt.Println(*val, party.ID)
		//计算消息
	}
	//需要处理的信息

	MRoundContent := StartRoundContent{1, 1, 1}

	//本地计算消息位置1，向每一个参与方广播相同消息的时候使用
	Msg := network.Message{FromID: "a", ToID: "", MContent: &MRoundContent}

	//广播消息
	for _, mparty := range Net.Parties {
		//本地计算消息位置2，向每一个参与方广播不同消息使用

		if mparty.ID != party.ID {
			Msg.ToID = mparty.ID
			Net.Channels[mparty.ID] <- &Msg
		}

	}
}
