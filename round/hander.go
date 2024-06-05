package round

import (
	"sync"

	"github.com/lianghuiqiang9/smt/network"
)

type RoundFunc func(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup)

func MRound(MroundFunc RoundFunc, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {

	var wg sync.WaitGroup
	wg.Add(Net.Parties[0].N)
	for i := 0; i < Net.Parties[0].N; i++ {
		go MroundFunc(&Net.Parties[i], Net, SecretInfo, &wg)
	}
	wg.Wait()
}
func MRoundT(MroundFunc RoundFunc, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {

	var wg sync.WaitGroup
	wg.Add(Net.Parties[0].T)
	for i := 0; i < Net.Parties[0].T; i++ {
		go MroundFunc(&Net.Parties[i], Net, SecretInfo, &wg)
	}
	wg.Wait()
}
