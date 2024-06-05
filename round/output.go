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

	//本地接受消息
	for i := 0; i < party.N-1; i++ {
		val := <-Net.Channels[party.ID] // 出 chan
		fmt.Println(*val, party.ID)

		//本地计算消息
	}

	MRoundContent := StartRoundContent{2, 1, 1}
	MRoundContent.DoSomething(party, Net, SecertInfo)

}
