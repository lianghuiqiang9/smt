package tskeygen

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/vss"
	"github.com/lianghuiqiang9/smt/zk"

	"github.com/cronokirby/safenum"
	"github.com/lianghuiqiang9/smt/paillier"
	// "github.com/taurusgroup/multi-party-sig/pkg/paillier"
)

type Round3Info struct {
	FromID  string
	FromNum int
	//VSS要发送的内容Cij和A
	VssEncyi   *paillier.Ciphertext
	VssAx      map[int]*big.Int
	VssAy      map[int]*big.Int
	Round3logp *zk.Logp

	//MtA要发送的消息
	Bx             *big.Int
	By             *big.Int
	Gi             *paillier.Ciphertext
	Round3logstarp *zk.Logstarp
}

func (p *Round3Info) DoSomething(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	//verify the logp
	Net.Mtx.Lock()
	flag := p.Round3logp.LogVerify(Net.Hash, party.Curve, Net.Parties[p.FromNum].Xix, Net.Parties[p.FromNum].Xiy)
	Net.Mtx.Unlock()

	if !flag {
		fmt.Println("error", p.FromID)
	}
	plaintxt, _ := SecretInfo[party.ID].PaillierSecertKey.Dec(p.VssEncyi)
	yij := plaintxt.Big()
	//vssverify
	vss.VssVerifySingleParty(p.FromNum, yij, p.VssAx, p.VssAy, party, Net, SecretInfo)
	//compute yi
	SecretInfo[party.ID].Y.Add(SecretInfo[party.ID].Y, yij)

	//run MtA
	//verify the logstarp
	Net.Mtx.Lock()
	flag2 := p.Round3logstarp.LogstarVerify(Net.Hash, Net.Parties[p.FromNum].Curve, Net.Parties[p.FromNum].Aux, Net.Parties[p.FromNum].PaillierPublickey, p.Gi, Net.Parties[p.FromNum].Xix, Net.Parties[p.FromNum].Xiy)
	Net.Mtx.Unlock()
	if !flag2 {
		fmt.Println("error", p.FromID)
	}

	party.Gammax, party.Gammay = party.Curve.Add(party.Gammax, party.Gammay, p.Bx, p.By)
	//Save every Gj here. Note that you need to make a map first
	SecretInfo[party.ID].MtAEncB[p.FromID] = p.Gi
}

func Round3(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()
	party.Rho = new(big.Int).Set(SecretInfo[party.ID].Rhoi)

	for i := 0; i < party.N-1; i++ {
		val := <-Net.Channels[party.ID]
		val.MContent.DoSomething(party, Net, SecretInfo)
	}
	//The next step should be to run the VSS and MultiAdd sub-protocols, and here we will put them into the main protocol for the sake of unification.
	party.Xix, party.Xiy = SecretInfo[party.ID].Xix, SecretInfo[party.ID].Xiy
	//broadcast the Gammaix, Gammaiy, and store the Gammaix，Gammaiy
	Bx, By := SecretInfo[party.ID].Gammaix, SecretInfo[party.ID].Gammaiy
	Gammax := new(big.Int).Set(Bx)
	Gammay := new(big.Int).Set(By)
	party.Gammax, party.Gammay = Gammax, Gammay

	Gammaix := new(big.Int).Set(Bx)
	Gammaiy := new(big.Int).Set(By)
	party.Gammaix, party.Gammaiy = Gammaix, Gammaiy

	vss.VssShareWithEncy(party, Net, SecretInfo)

	//generate the zklog proof
	Net.Mtx.Lock()
	Round3logp := zk.LogProve(Net.Hash, party.Curve, party.Xix, party.Xiy, SecretInfo[party.ID].Xi)
	Net.Mtx.Unlock()
	//run the MultiAdd protocol
	x := new(safenum.Int).SetBig(SecretInfo[party.ID].Xi, SecretInfo[party.ID].Xi.BitLen())

	ct, v := party.PaillierPublickey.Enc(x)
	//Unbroadcast messages should not be put directly into the party to avoid misunderstandings.
	//party.EncXi = ct
	SecretInfo[party.ID].EncXi = ct

	//generate the zkencp
	Net.Mtx.Lock()
	Round3logstarp := zk.LogstarProve(Net.Hash, party.Curve, party.Aux, party.PaillierPublickey, ct, party.Xix, party.Xiy, x, v)
	Net.Mtx.Unlock()

	//Broadcast messages
	for _, mparty := range Net.Parties {
		if mparty.ID != party.ID {

			MRoundContent := Round3Info{party.ID, party.Num, SecretInfo[party.ID].VssEncy[mparty.ID], SecretInfo[party.ID].VssAx, SecretInfo[party.ID].VssAy, Round3logp, Bx, By, ct, Round3logstarp}
			Msg := network.Message{FromID: party.ID, ToID: "", MContent: &MRoundContent}
			Msg.ToID = mparty.ID
			Net.Channels[mparty.ID] <- &Msg
		}

	}

}
