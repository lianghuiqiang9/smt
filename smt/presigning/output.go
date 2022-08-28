package presigning

import (
	"math/big"
	"sync"

	"github.com/lianghuiqiang9/smt/network"
)

func Output(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()

	aibi := new(big.Int).Mul(SecretInfo[party.ID].Ki, SecretInfo[party.ID].Wi)

	aibi = aibi.Mod(aibi, party.Curve.Params().N)
	SecretInfo[party.ID].Chi = aibi

	for i := 0; i < party.T-1; i++ {
		val := <-net.Channels[party.ID] // 出 chan
		val.MContent.DoSomething(party, net, SecretInfo)
		//本地计算消息
	}
}
