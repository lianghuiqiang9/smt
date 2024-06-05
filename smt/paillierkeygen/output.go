package paillierkeygen

import (
	"sync"

	"github.com/lianghuiqiang9/smt/network"
)

func Output(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()

	for i := 0; i < party.N-1; i++ {
		val := <-Net.Channels[party.ID]
		val.MContent.DoSomething(party, Net, SecretInfo)

	}
}
