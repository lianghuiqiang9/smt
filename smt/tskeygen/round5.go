package tskeygen

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/zk"
)

type Round5Info struct {
	FromID  string
	FromNum int
	Deltaix *big.Int
	Deltaiy *big.Int
	logp1   *zk.Logp
	logp2   *zk.Logp
	Deltai  *big.Int
}

func (p *Round5Info) DoSomething(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {

	//Verify two zk
	Net.Mtx.Lock()
	flag := p.logp1.LogVerify(Net.Hash, Net.Parties[p.FromNum].Curve, Net.Parties[p.FromNum].Yix, Net.Parties[p.FromNum].Yiy)
	flag1 := p.logp2.LogVerify1(Net.Hash, Net.Parties[p.FromNum].Curve, p.Deltaix, p.Deltaiy, Net.Parties[p.FromNum].Gammax, Net.Parties[p.FromNum].Gammay)
	Net.Mtx.Unlock()
	if !flag {
		fmt.Println("error", p.FromID)
	}
	if !flag1 {
		fmt.Println("error", p.FromID)
	}
	//Calculate the Delta and verify the Delta
	party.Delta = party.Delta.Add(party.Delta, p.Deltai)
	party.Delta = party.Delta.Mod(party.Delta, party.Curve.Params().N)
	party.Deltax, party.Deltay = party.Curve.Add(party.Deltax, party.Deltay, p.Deltaix, p.Deltaiy)
}

func Round5(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()

	aibi := new(big.Int).Mul(SecretInfo[party.ID].Xi, SecretInfo[party.ID].Gammai)
	aibi = aibi.Mod(aibi, party.Curve.Params().N)
	SecretInfo[party.ID].Deltai = aibi

	for i := 0; i < party.N-1; i++ {
		val := <-Net.Channels[party.ID]
		val.MContent.DoSomething(party, Net, SecretInfo)
	}

	//Send two zk, and Delta, and output.
	Deltaix, Deltaiy := party.Curve.ScalarMult(party.Gammax, party.Gammay, SecretInfo[party.ID].Xi.Bytes())
	Deltaxx := new(big.Int).Set(Deltaix)
	Deltayy := new(big.Int).Set(Deltaiy)
	SecretInfo[party.ID].Deltaix, SecretInfo[party.ID].Deltaiy = Deltaxx, Deltayy

	Net.Mtx.Lock()
	logp1 := zk.LogProve(Net.Hash, party.Curve, party.Yix, party.Yiy, SecretInfo[party.ID].Y)
	logp2 := zk.LogProve1(Net.Hash, party.Curve, Deltaix, Deltaiy, party.Gammax, party.Gammay, SecretInfo[party.ID].Xi)
	Net.Mtx.Unlock()
	Deltai := new(big.Int).Set(SecretInfo[party.ID].Deltai)

	MRoundContent := Round5Info{party.ID, party.Num, Deltaix, Deltaiy, logp1, logp2, Deltai}
	Msg := network.Message{FromID: party.ID, ToID: "", MContent: &MRoundContent}

	for _, mparty := range Net.Parties {
		if mparty.ID != party.ID {
			Msg.ToID = mparty.ID
			Net.Channels[mparty.ID] <- &Msg
		}

	}

}
