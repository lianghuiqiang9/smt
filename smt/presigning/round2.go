package presigning

import (
	"fmt"
	"math/big"

	"github.com/lianghuiqiang9/smt/modfiysm2"
	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/zk"

	"sync"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
)

type Round2Info struct {
	FromID   string
	FromNum  int
	Eji      *paillier.Ciphertext
	Dji      *paillier.Ciphertext
	Encstarp *zk.Proof
}

func (p *Round2Info) DoSomething(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {

	public := zk.Public{
		Kv:       party.EncWi,
		Dv:       p.Eji,
		Fp:       p.Dji,
		Xx:       net.Parties[p.FromNum].Rix,
		Xy:       net.Parties[p.FromNum].Riy,
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

	//解密Eij
	alphaij, _ := SecretInfo[party.ID].PaillierSecertKey.Dec(p.Eji)

	//计算detai
	alphabeta := alphaij.Abs().Big()
	alphabeta = alphabeta.Add(alphabeta, SecretInfo[party.ID].Beta2[p.FromID])
	SecretInfo[party.ID].Chi = SecretInfo[party.ID].Chi.Add(SecretInfo[party.ID].Chi, alphabeta)
	SecretInfo[party.ID].Chi = SecretInfo[party.ID].Chi.Mod(SecretInfo[party.ID].Chi, party.Curve.Params().N)

}

func Round2(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()

	MtAEncW := make(map[string]*paillier.Ciphertext)
	SecretInfo[party.ID].MtAEncW = MtAEncW

	//这里是用来计算R
	Rx := new(big.Int).Set(SecretInfo[party.ID].Kix)
	Ry := new(big.Int).Set(SecretInfo[party.ID].Kiy)
	party.Rx, party.Ry = Rx, Ry

	//多存了Rix，有什么用处呢？？
	Rix := new(big.Int).Set(SecretInfo[party.ID].Kix)
	Riy := new(big.Int).Set(SecretInfo[party.ID].Kiy)
	party.Rix, party.Riy = Rix, Riy

	//注意这里呀，只有T个参与方
	for i := 0; i < party.T-1; i++ {
		val := <-net.Channels[party.ID] // 出 chan
		val.MContent.DoSomething(party, net, SecretInfo)
	}
	//将EncWi记录了下来。
	party.EncWi = SecretInfo[party.ID].EncWi

	//make一个链接。存储Beta
	Beta2 := make(map[string]*big.Int)
	SecretInfo[party.ID].Beta2 = Beta2

	for i := 0; i < party.T; i++ {
		if net.Parties[i].ID != party.ID {
			//随机Beta，然后加密
			Betaj, _ := modfiysm2.RandFieldElement(party.Curve, nil)
			Betajneg := new(big.Int).Neg(Betaj)
			Betajnegsafe := new(safenum.Int).SetBig(Betajneg, Betajneg.BitLen())
			EBetajnegsafe, fij := net.Parties[i].PaillierPublickey.Enc(Betajnegsafe)
			//Beta2应该存储到SecretInfo中。
			SecretInfo[party.ID].Beta2[net.Parties[i].ID] = Betaj

			//Wix,Wiy,Kix,Kiy,wi,ki。其中都是他们的椭圆曲线点
			//Ai,Bi,ai,bi

			//点乘Gammai和Gj，换了MtAEncB换成MtAEncW，和Gammai换成Ki
			Gj := SecretInfo[party.ID].MtAEncW[net.Parties[i].ID]
			Eji := (*paillier.Ciphertext).Clone(Gj)
			Kisafe := new(safenum.Int).SetBig(SecretInfo[party.ID].Ki, SecretInfo[party.ID].Ki.BitLen())
			Eji = Eji.Mul(net.Parties[i].PaillierPublickey, Kisafe)
			//加法，然后Eji计算完毕
			Eji = Eji.Add(net.Parties[i].PaillierPublickey, EBetajnegsafe)
			//计算Dji
			Dji, gij := party.PaillierPublickey.Enc(Betajnegsafe)
			//计算EncstarP,Gammaix,Gammaiy换成Rix,Riy
			public := zk.Public{
				Kv:       Gj,
				Dv:       Eji,
				Fp:       Dji,
				Xx:       party.Rix, //ki的kiG
				Xy:       party.Riy,
				Prover:   party.PaillierPublickey,
				Verifier: net.Parties[i].PaillierPublickey,
				Aux:      net.Parties[i].Aux,
			}
			private := zk.Private{
				X: Kisafe,
				Y: Betajnegsafe,
				S: fij,
				R: gij,
			}
			net.Mtx.Lock()
			proof := zk.EncstarProof(net.Hash, party.Curve, public, private)
			net.Mtx.Unlock()

			MRoundContent := Round2Info{party.ID, party.Num, Eji, Dji, proof}
			//本地计算消息位置1，向每一个参与方广播相同消息的时候使用
			Msg := network.Message{FromID: party.ID, ToID: "", MContent: &MRoundContent}

			Msg.ToID = net.Parties[i].ID
			net.Channels[net.Parties[i].ID] <- &Msg
		}
	}

}
