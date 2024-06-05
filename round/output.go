package round

import (
	"fmt"
	"sync"

	"github.com/lianghuiqiang9/smt/network"
)

type OutputContent struct {
	MRoundNumber int
	Minfo        int
	Num          int
}

func (p *OutputContent) DoSomething(party *network.Party, SecertInfo network.MSecretPartiesInfoMap) {
	fmt.Println("this is the Round number ", p.MRoundNumber)
}

func Output(party *network.Party, Net *network.Network, SecertInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()

	for i := 0; i < party.N-1; i++ {
		val := <-Net.Channels[party.ID]
		fmt.Println(*val, party.ID)

	}

	MRoundContent := StartRoundContent{2, 1, 1}
	MRoundContent.DoSomething(party, Net, SecertInfo)

}
