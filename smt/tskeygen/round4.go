package tskeygen

import (
	"fmt"
	"github.com/cronokirby/safenum"
	"github.com/lianghuiqiang9/smt/modfiysm2"
	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/paillier"
	"github.com/lianghuiqiang9/smt/zk"
	"math/big"
	"sync"
)

type Round4Info struct {
	FromID   string
	FromNum  int
	Eji      *paillier.Ciphertext
	Dji      *paillier.Ciphertext
	Encstarp *zk.Proof
}

func (p *Round4Info) DoSomething(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	//verfiy the Encstarp,

	public := zk.Public{
		Kv:       party.EncXi,
		Dv:       p.Eji,
		Fp:       p.Dji,
		Xx:       Net.Parties[p.FromNum].Gammaix,
		Xy:       Net.Parties[p.FromNum].Gammaiy,
		Prover:   Net.Parties[p.FromNum].PaillierPublickey,
		Verifier: party.PaillierPublickey,
		Aux:      party.Aux,
	}
	Net.Mtx.Lock()
	flag := p.Encstarp.EncstarVerify(Net.Hash, public)
	Net.Mtx.Unlock()
	if !flag {
		fmt.Println("error", p.FromID)
	}

	//decrypt the Eij
	alphaij, _ := SecretInfo[party.ID].PaillierSecertKey.Dec(p.Eji)

	//compute the detai
	alphabeta := alphaij.Abs().Big()
	alphabeta = alphabeta.Add(alphabeta, SecretInfo[party.ID].Beta[p.FromID])
	SecretInfo[party.ID].Deltai = SecretInfo[party.ID].Deltai.Add(SecretInfo[party.ID].Deltai, alphabeta)
	SecretInfo[party.ID].Deltai = SecretInfo[party.ID].Deltai.Mod(SecretInfo[party.ID].Deltai, party.Curve.Params().N)
}

func Round4(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()
	Y := new(big.Int)
	Y = SecretInfo[party.ID].Vssy[party.ID]
	SecretInfo[party.ID].Y = Y

	MtAEncB := make(map[string]*paillier.Ciphertext)
	SecretInfo[party.ID].MtAEncB = MtAEncB

	for i := 0; i < party.N-1; i++ {
		val := <-Net.Channels[party.ID]
		val.MContent.DoSomething(party, Net, SecretInfo)
	}

	party.Yix, party.Yiy = party.Curve.ScalarBaseMult(SecretInfo[party.ID].Y.Bytes())
	party.EncXi = SecretInfo[party.ID].EncXi

	//compute A, because all the information used is public.
	Ax := new(big.Int)
	Ay := new(big.Int)
	for _, partyi := range Net.Parties {
		Ax, Ay = partyi.Curve.Add(Ax, Ay, partyi.Xix, partyi.Xiy)
	}
	party.Ax = Ax
	party.Ay = Ay

	//Run MtA to check whether the Gj has been stored

	Beta := make(map[string]*big.Int)
	SecretInfo[party.ID].Beta = Beta

	for _, mparty := range Net.Parties {
		if mparty.ID != party.ID {

			//Random choose beta, then encrypt it.
			Betaj, _ := modfiysm2.RandFieldElement(party.Curve, nil)
			Betajneg := new(big.Int).Neg(Betaj)
			Betajnegsafe := new(safenum.Int).SetBig(Betajneg, Betajneg.BitLen())
			EBetajnegsafe, fij := mparty.PaillierPublickey.Enc(Betajnegsafe)

			//store the Beta to the SecretInfo.
			SecretInfo[party.ID].Beta[mparty.ID] = Betaj

			//dot multiplication Gammai and Gj
			Gj := SecretInfo[party.ID].MtAEncB[mparty.ID]
			Eji := (*paillier.Ciphertext).Clone(Gj)
			Gammaisafe := new(safenum.Int).SetBig(SecretInfo[party.ID].Gammai, SecretInfo[party.ID].Gammai.BitLen())
			Eji = Eji.Mul(mparty.PaillierPublickey, Gammaisafe)
			//Add, the finish the Eji
			Eji = Eji.Add(mparty.PaillierPublickey, EBetajnegsafe)
			//计算Dji
			Dji, gij := party.PaillierPublickey.Enc(Betajnegsafe)
			//computate EncstarP

			public := zk.Public{
				Kv:       Gj,
				Dv:       Eji,
				Fp:       Dji,
				Xx:       party.Gammaix,
				Xy:       party.Gammaiy,
				Prover:   party.PaillierPublickey,
				Verifier: mparty.PaillierPublickey,
				Aux:      mparty.Aux,
			}
			private := zk.Private{
				X: Gammaisafe,
				Y: Betajnegsafe,
				S: fij,
				R: gij,
			}
			Net.Mtx.Lock()
			proof := zk.EncstarProof(Net.Hash, party.Curve, public, private)
			Net.Mtx.Unlock()
			MRoundContent := Round4Info{party.ID, party.Num, Eji, Dji, proof}
			Msg := network.Message{FromID: party.ID, ToID: "", MContent: &MRoundContent}

			Msg.ToID = mparty.ID
			Net.Channels[mparty.ID] <- &Msg
		}

	}

}
