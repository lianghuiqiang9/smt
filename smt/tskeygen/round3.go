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
	//验证logp
	Net.Mtx.Lock()
	flag := p.Round3logp.LogVerify(Net.Hash, party.Curve, Net.Parties[p.FromNum].Xix, Net.Parties[p.FromNum].Xiy)
	Net.Mtx.Unlock()

	if !flag {
		fmt.Println("error", p.FromID)
	}
	//关于A,这个又没有广播，所以不在这里做。
	//验证y是否合理。解密yij,注意这里是VssEnci，不是Gi，Gi在MtA里面
	plaintxt, _ := SecretInfo[party.ID].PaillierSecertKey.Dec(p.VssEncyi)
	yij := plaintxt.Big()
	//vssverify
	vss.VssVerifySingleParty(p.FromNum, yij, p.VssAx, p.VssAy, party, Net, SecretInfo)
	//计算yi
	SecretInfo[party.ID].Y.Add(SecretInfo[party.ID].Y, yij)

	//执行MtA
	//验证logstarp
	Net.Mtx.Lock()
	flag2 := p.Round3logstarp.LogstarVerify(Net.Hash, Net.Parties[p.FromNum].Curve, Net.Parties[p.FromNum].Aux, Net.Parties[p.FromNum].PaillierPublickey, p.Gi, Net.Parties[p.FromNum].Xix, Net.Parties[p.FromNum].Xiy)
	Net.Mtx.Unlock()
	if !flag2 {
		fmt.Println("error", p.FromID)
	}

	//对Bx，By进行操作
	party.Gammax, party.Gammay = party.Curve.Add(party.Gammax, party.Gammay, p.Bx, p.By)
	//在这里对每一个Gj，将Gj存下来吧。注意要先make一个map
	SecretInfo[party.ID].MtAEncB[p.FromID] = p.Gi
}

func Round3(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()
	party.Rho = new(big.Int).Set(SecretInfo[party.ID].Rhoi) //想好了new一个，最后还是没有new，浪费了一个小时

	for i := 0; i < party.N-1; i++ {
		val := <-Net.Channels[party.ID] // 出 chan
		val.MContent.DoSomething(party, Net, SecretInfo)
	}
	//接下来应该是运行VSS和MultiAdd子协议，在这里为了统一，我们将其放到主协议中。
	party.Xix, party.Xiy = SecretInfo[party.ID].Xix, SecretInfo[party.ID].Xiy
	//广播Gammaix,Gammaiy，保存一下Gammaix，Gammaiy
	Bx, By := SecretInfo[party.ID].Gammaix, SecretInfo[party.ID].Gammaiy
	Gammax := new(big.Int).Set(Bx)
	Gammay := new(big.Int).Set(By)
	party.Gammax, party.Gammay = Gammax, Gammay

	Gammaix := new(big.Int).Set(Bx)
	Gammaiy := new(big.Int).Set(By)
	party.Gammaix, party.Gammaiy = Gammaix, Gammaiy

	vss.VssShareWithEncy(party, Net, SecretInfo)

	//生成zklog证明，Xi，是Xix,Xiy的私钥
	Net.Mtx.Lock()
	Round3logp := zk.LogProve(Net.Hash, party.Curve, party.Xix, party.Xiy, SecretInfo[party.ID].Xi)
	Net.Mtx.Unlock()
	//运行MultiAdd协议
	x := new(safenum.Int).SetBig(SecretInfo[party.ID].Xi, SecretInfo[party.ID].Xi.BitLen())

	ct, v := party.PaillierPublickey.Enc(x)
	//未广播的消息尽量还是不要直接放到party里面，免得引起误会。//	party.EncXi = ct
	SecretInfo[party.ID].EncXi = ct

	//生成zkencp
	Net.Mtx.Lock()
	Round3logstarp := zk.LogstarProve(Net.Hash, party.Curve, party.Aux, party.PaillierPublickey, ct, party.Xix, party.Xiy, x, v)
	Net.Mtx.Unlock()

	//广播消息
	for _, mparty := range Net.Parties {
		if mparty.ID != party.ID {

			MRoundContent := Round3Info{party.ID, party.Num, SecretInfo[party.ID].VssEncy[mparty.ID], SecretInfo[party.ID].VssAx, SecretInfo[party.ID].VssAy, Round3logp, Bx, By, ct, Round3logstarp}
			Msg := network.Message{FromID: party.ID, ToID: "", MContent: &MRoundContent}
			Msg.ToID = mparty.ID
			Net.Channels[mparty.ID] <- &Msg
		}

	}

}
