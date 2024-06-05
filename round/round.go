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

	}

	MRoundContent := StartRoundContent{1, 1, 1}
	Msg := network.Message{FromID: "a", ToID: "", MContent: &MRoundContent}

	for _, mparty := range Net.Parties {

		if mparty.ID != party.ID {
			Msg.ToID = mparty.ID
			Net.Channels[mparty.ID] <- &Msg
		}

	}
}
