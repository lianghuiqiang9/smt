package signing

import (
	"math/big"
	"sync"

	"github.com/lianghuiqiang9/smt/network"
)

func Output(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()

	party.S = new(big.Int).Set(SecretInfo[party.ID].S)

	for i := 0; i < party.T-1; i++ {
		val := <-Net.Channels[party.ID] // 出 chan
		val.MContent.DoSomething(party, Net, SecretInfo)
		//本地计算消息
	}
	//s=sum(s)
	party.S.Mod(party.S, party.Curve.Params().N)
	//s=(s-r)modn
	party.S.Sub(party.S, party.R)
	party.S.Mod(party.S, party.Curve.Params().N)
}
