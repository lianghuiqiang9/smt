package tskeygen

import (
	"crypto/rand"

	"github.com/lianghuiqiang9/smt/modfiysm2"
	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/zk"

	"math/big"
	"sync"
)

type Round1Info struct {
	FromID string
	V      *big.Int
}

func (p *Round1Info) DoSomething(party *network.Party, Net *network.Network, SecertInfo network.MSecretPartiesInfoMap) {
	SecertInfo[party.ID].V[p.FromID] = p.V
}

func Round1(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()

	xi, _ := modfiysm2.RandFieldElement(party.Curve, nil)
	gammai, _ := modfiysm2.RandFieldElement(party.Curve, nil)
	Xix, Xiy := party.Curve.ScalarBaseMult(xi.Bytes())
	Gammaix, Gammaiy := party.Curve.ScalarBaseMult(gammai.Bytes())

	bf := make([]byte, 32)
	rand.Read(bf)
	rhoi := new(big.Int).SetBytes(bf)

	bf2 := make([]byte, 32)
	rand.Read(bf2)
	ui := new(big.Int).SetBytes(bf2)

	Net.Mtx.Lock()
	Net.Hash.Write(zk.BytesCombine(party.Rtig.Bytes(), Xix.Bytes(), Xiy.Bytes(), Gammaix.Bytes(), Gammaiy.Bytes(), rhoi.Bytes(), ui.Bytes()))
	bytes := Net.Hash.Sum(nil)

	Vi := new(big.Int).SetBytes(bytes)
	Net.Hash.Reset()
	Net.Mtx.Unlock()

	SecretInfo[party.ID].Xi = xi
	SecretInfo[party.ID].Gammai = gammai
	SecretInfo[party.ID].Xix = Xix
	SecretInfo[party.ID].Xiy = Xiy
	SecretInfo[party.ID].Gammaix = Gammaix
	SecretInfo[party.ID].Gammaiy = Gammaiy
	SecretInfo[party.ID].Rhoi = new(big.Int).SetBytes(bf)
	SecretInfo[party.ID].Ui = ui

	Round1Content := Round1Info{party.ID, Vi}
	Msg := network.Message{FromID: party.ID, ToID: "", MContent: &Round1Content}
	for _, mparty := range Net.Parties {
		if mparty.ID != party.ID {
			Msg.ToID = mparty.ID
			Net.Channels[mparty.ID] <- &Msg
		}
	}

}
