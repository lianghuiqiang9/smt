package tskeygen

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/lianghuiqiang9/smt/modfiysm2"
	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/zk"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
)

type Round4Info struct {
	FromID   string
	FromNum  int
	Eji      *paillier.Ciphertext
	Dji      *paillier.Ciphertext
	Encstarp *zk.Proof
}

func (p *Round4Info) DoSomething(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	//验证Encstarp,p是发送方的i，自己是j

	public := zk.Public{
		Kv:       party.EncXi,
		Dv:       p.Eji,
		Fp:       p.Dji,
		Xx:       net.Parties[p.FromNum].Gammaix,
		Xy:       net.Parties[p.FromNum].Gammaiy,
		Prover:   net.Parties[p.FromNum].PaillierPublickey,
		Verifier: party.PaillierPublickey,
		Aux:      party.Aux,
	}
	net.Mtx.Lock()
	flag := p.Encstarp.EncstarVerify(net.Hash, public)
	net.Mtx.Unlock()
	if flag != true {
		fmt.Println("error", p.FromID)
	}
	//写到现在，好像自己已经很熟悉这个流程了，加油，希望晚上也写的时候，不会出现错误。

	//解密Eij
	alphaij, _ := SecretInfo[party.ID].PaillierSecertKey.Dec(p.Eji)

	//计算detai
	alphabeta := alphaij.Abs().Big()
	alphabeta = alphabeta.Add(alphabeta, SecretInfo[party.ID].Beta[p.FromID])
	SecretInfo[party.ID].Deltai = SecretInfo[party.ID].Deltai.Add(SecretInfo[party.ID].Deltai, alphabeta)
	SecretInfo[party.ID].Deltai = SecretInfo[party.ID].Deltai.Mod(SecretInfo[party.ID].Deltai, party.Curve.Params().N)
}

func Round4(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()
	Y := new(big.Int)
	Y = SecretInfo[party.ID].Vssy[party.ID]
	SecretInfo[party.ID].Y = Y

	MtAEncB := make(map[string]*paillier.Ciphertext)
	SecretInfo[party.ID].MtAEncB = MtAEncB

	for i := 0; i < party.N-1; i++ {
		val := <-net.Channels[party.ID] // 出 chan
		val.MContent.DoSomething(party, net, SecretInfo)
	}

	party.Yix, party.Yiy = party.Curve.ScalarBaseMult(SecretInfo[party.ID].Y.Bytes())
	party.EncXi = SecretInfo[party.ID].EncXi

	//计算A,因为用的都是公共信息。
	Ax := new(big.Int)
	Ay := new(big.Int)
	for _, partyi := range net.Parties {
		Ax, Ay = partyi.Curve.Add(Ax, Ay, partyi.Xix, partyi.Xiy)
	}
	party.Ax = Ax
	party.Ay = Ay

	//执行MtA，检查Gj是否存储完毕

	//make一个map,存储Beta
	Beta := make(map[string]*big.Int)
	SecretInfo[party.ID].Beta = Beta

	for _, mparty := range net.Parties {
		if mparty.ID != party.ID {

			//随机Beta，然后加密
			Betaj, _ := modfiysm2.RandFieldElement(party.Curve, nil)
			Betajneg := new(big.Int).Neg(Betaj)
			Betajnegsafe := new(safenum.Int).SetBig(Betajneg, Betajneg.BitLen())
			EBetajnegsafe, fij := mparty.PaillierPublickey.Enc(Betajnegsafe)

			//Beta应该存储到SecretInfo中。
			SecretInfo[party.ID].Beta[mparty.ID] = Betaj

			//点乘Gammai和Gj
			Gj := SecretInfo[party.ID].MtAEncB[mparty.ID]
			Eji := (*paillier.Ciphertext).Clone(Gj)
			Gammaisafe := new(safenum.Int).SetBig(SecretInfo[party.ID].Gammai, SecretInfo[party.ID].Gammai.BitLen())
			Eji = Eji.Mul(mparty.PaillierPublickey, Gammaisafe)
			//加法，然后Eji计算完毕
			Eji = Eji.Add(mparty.PaillierPublickey, EBetajnegsafe)
			//计算Dji
			Dji, gij := party.PaillierPublickey.Enc(Betajnegsafe)
			//计算EncstarP

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
			net.Mtx.Lock()
			proof := zk.EncstarProof(net.Hash, party.Curve, public, private)
			net.Mtx.Unlock()
			MRoundContent := Round4Info{party.ID, party.Num, Eji, Dji, proof}
			//本地计算消息位置1，向每一个参与方广播相同消息的时候使用
			Msg := network.Message{FromID: party.ID, ToID: "", MContent: &MRoundContent}

			//这里也是单独的情况下

			Msg.ToID = mparty.ID
			net.Channels[mparty.ID] <- &Msg
		}

	}

}
