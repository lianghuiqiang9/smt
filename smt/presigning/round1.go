package presigning

import (
	"fmt"

	"github.com/lianghuiqiang9/smt/modfiysm2"
	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/vss"
	"github.com/lianghuiqiang9/smt/zk"

	"math/big"
	"sync"

	"github.com/cronokirby/safenum"
	"github.com/lianghuiqiang9/smt/paillier"
)

type Round1Info struct {
	FromID         string
	FromNum        int
	Ax             *big.Int
	Ay             *big.Int
	Bx             *big.Int
	By             *big.Int
	Gi             *paillier.Ciphertext //ENC(wi)
	Round1logstarp *zk.Logstarp
}

func (p *Round1Info) DoSomething(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {

	Net.Mtx.Lock()
	flag2 := p.Round1logstarp.LogstarVerify(Net.Hash, Net.Parties[p.FromNum].Curve, Net.Parties[p.FromNum].Aux, Net.Parties[p.FromNum].PaillierPublickey, p.Gi, p.Ax, p.Ay)
	Net.Mtx.Unlock()

	if flag2 != true {
		fmt.Println("error", p.FromID)
	}

	party.Rx, party.Ry = party.Curve.Add(party.Rx, party.Ry, p.Bx, p.By)
	SecretInfo[party.ID].MtAEncW[p.FromID] = p.Gi

}

func Round1(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()
	ki, _ := modfiysm2.RandFieldElement(party.Curve, nil)
	SecretInfo[party.ID].Ki = ki

	Kix, Kiy := party.Curve.ScalarBaseMult(ki.Bytes())
	SecretInfo[party.ID].Kix, SecretInfo[party.ID].Kiy = Kix, Kiy

	lambda := vss.Lagrange(Net, party.ID, party.T)
	wi := new(big.Int).Mul(lambda, SecretInfo[party.ID].Y)
	SecretInfo[party.ID].Wi = wi

	Wix, Wiy := party.Curve.ScalarBaseMult(wi.Bytes())
	SecretInfo[party.ID].Wix, SecretInfo[party.ID].Wiy = Wix, Wiy

	//verify the A=sum(lambdai*Yi)
	Wx := new(big.Int)
	Wy := new(big.Int)
	for i := 0; i < party.T; i++ {
		if Net.Parties[i].ID != party.ID {
			lambda := vss.Lagrange(Net, Net.Parties[i].ID, party.T)
			Wix, Wiy := party.Curve.ScalarMult(Net.Parties[i].Yix, Net.Parties[i].Yiy, lambda.Bytes())
			Wx, Wy = party.Curve.Add(Wx, Wy, Wix, Wiy)
		}
	}
	Wx, Wy = party.Curve.Add(Wx, Wy, Wix, Wiy)

	flag := party.Ax.Cmp(Wx) == 0 && party.Ay.Cmp(Wy) == 0
	if flag != true {
		fmt.Println("error,please run presigning checken", party.ID)
	}

	x := new(safenum.Int).SetBig(wi, wi.BitLen())
	ct, v := party.PaillierPublickey.Enc(x)
	SecretInfo[party.ID].EncWi = ct

	Net.Mtx.Lock()
	Round1logstarp := zk.LogstarProve(Net.Hash, party.Curve, party.Aux, party.PaillierPublickey, ct, Wix, Wiy, x, v)
	Net.Mtx.Unlock()

	Round1Content := Round1Info{party.ID, party.Num, Wix, Wiy, Kix, Kiy, ct, Round1logstarp}
	Msg := network.Message{FromID: party.ID, ToID: "", MContent: &Round1Content}

	for i := 0; i < party.T; i++ {
		if Net.Parties[i].ID != party.ID {
			Msg.ToID = Net.Parties[i].ID
			Net.Channels[Net.Parties[i].ID] <- &Msg
		}
	}

}
