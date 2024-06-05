package tskeygen

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/zk"
)

type Round2Info struct {
	FromID  string
	Xix     *big.Int
	Xiy     *big.Int
	Gammaix *big.Int
	Gammaiy *big.Int
	Rhoi    *big.Int
	Ui      *big.Int
}

// Here's what to do in the third round according to Round2Info.
func (p *Round2Info) DoSomething(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	Net.Mtx.Lock()
	Net.Hash.Write(zk.BytesCombine(party.Rtig.Bytes(), p.Xix.Bytes(), p.Xiy.Bytes(), p.Gammaix.Bytes(), p.Gammaiy.Bytes(), p.Rhoi.Bytes(), p.Ui.Bytes()))
	bytes := Net.Hash.Sum(nil)
	Vi2 := new(big.Int).SetBytes(bytes)
	Net.Hash.Reset()
	Net.Mtx.Unlock()
	Vi3 := SecretInfo[party.ID].V[p.FromID]

	if Vi2.Cmp(Vi3) != 0 {
		fmt.Println("error", p.FromID)
	}
	//add the Rhoi to Rho.
	party.Rho.Add(party.Rho, p.Rhoi)

}

// Here's the news to be done in the second round.
func Round2(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()

	Vmap := make(map[string]*big.Int)
	SecretInfo[party.ID].V = Vmap

	for i := 0; i < party.N-1; i++ {
		val := <-Net.Channels[party.ID]
		val.MContent.DoSomething(party, Net, SecretInfo)
	}

	MRoundContent := Round2Info{party.ID, SecretInfo[party.ID].Xix, SecretInfo[party.ID].Xiy, SecretInfo[party.ID].Gammaix, SecretInfo[party.ID].Gammaiy, SecretInfo[party.ID].Rhoi, SecretInfo[party.ID].Ui}

	Msg := network.Message{FromID: party.ID, ToID: "", MContent: &MRoundContent}

	for _, mparty := range Net.Parties {
		if mparty.ID != party.ID {
			Msg.ToID = mparty.ID
			Net.Channels[mparty.ID] <- &Msg
		}

	}

}
