package signing

import (
	"math/big"
	"sync"

	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/zk"
)

type Round1Info struct {
	FromID  string
	FromNum int
	S       *big.Int
}

func (p *Round1Info) DoSomething(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	party.S.Add(party.S, p.S)
}

func Round1(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()

	msg := Net.Msg
	Net.Mtx.Lock()

	Net.Hash.Write(zk.BytesCombine(party.Rtig.Bytes(), party.Rho.Bytes(), party.Xx.Bytes(), party.Xy.Bytes()))
	bytes := Net.Hash.Sum(nil)

	Z := new(big.Int).SetBytes(bytes)
	Net.Hash.Reset()

	//compute e
	Net.Hash.Write(zk.BytesCombine(Z.Bytes(), msg))
	bytes2 := Net.Hash.Sum(nil)
	e := new(big.Int).SetBytes(bytes2)

	Net.Hash.Reset()
	Net.Mtx.Unlock()

	//compute r
	e.Add(e, party.Rx)
	r := new(big.Int).Mod(e, party.Curve.Params().N)

	party.R = r

	//compute s
	s := new(big.Int).Mul(SecretInfo[party.ID].Wi, r)
	s.Mod(s, party.Curve.Params().N)
	s.Add(s, SecretInfo[party.ID].Chi)
	s.Mod(s, party.Curve.Params().N)
	SecretInfo[party.ID].S = s

	Round1Content := Round1Info{party.ID, party.Num, s}
	Msg := network.Message{FromID: party.ID, ToID: "", MContent: &Round1Content}

	//Broadcast messages, without losing generality, only the first T participants are considered here
	for i := 0; i < party.T; i++ {
		if Net.Parties[i].ID != party.ID {
			Msg.ToID = Net.Parties[i].ID
			Net.Channels[Net.Parties[i].ID] <- &Msg
		}
	}
}
