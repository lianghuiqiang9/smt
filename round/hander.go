package round

import (
	"sync"

	"github.com/lianghuiqiang9/smt/network"
)

type RoundFunc func(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup)

func MRound(MroundFunc RoundFunc, net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {

	var wg sync.WaitGroup
	wg.Add(net.Parties[0].N)
	for i := 0; i < net.Parties[0].N; i++ {
		go MroundFunc(&net.Parties[i], net, SecretInfo, &wg)
	}
	wg.Wait()
}
func MRoundT(MroundFunc RoundFunc, net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {

	var wg sync.WaitGroup
	wg.Add(net.Parties[0].T)
	for i := 0; i < net.Parties[0].T; i++ {
		//开启N个线程, 每一个运行相当于参与方在运行, 这里完成的是info的相关工作.
		go MroundFunc(&net.Parties[i], net, SecretInfo, &wg)
	}
	wg.Wait()
}
