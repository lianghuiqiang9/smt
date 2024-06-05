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
	Msg := network.Message{FromID: "a", ToID: "", MContent: &MStartRoundContent}
	for _, mparty := range Net.Parties {

		if mparty.ID != party.ID {
			Net.Channels[mparty.ID] <- &Msg
		}
	}
}
