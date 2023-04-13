package paillierkeygen

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"

	//	paillierbig "github.com/roasbeef/go-go-gadget-paillier"

	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/paillier"

	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	//	"github.com/taurusgroup/multi-party-sig/pkg/paillier"

	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	mod "github.com/taurusgroup/multi-party-sig/pkg/zk/mod"
	prm "github.com/taurusgroup/multi-party-sig/pkg/zk/prm"
)

// 这里定义每轮需要发送的消息
type Round1Info struct {
	FromID            string
	Rtigi             *big.Int
	PaillierPublickey *paillier.PublicKey
	//	Paillierpubkey    *paillierbig.PublicKey

	Aux      *pedersen.Parameters
	PrmPubic *prm.Public
	PrmProof *prm.Proof
	ModPubic *mod.Public
	ModProof *mod.Proof
}

// 定义的每一个Content都要有一个这样的方法来引入，方便万能指针指向
func (p *Round1Info) DoSomething(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	flag1 := p.PrmProof.Verify(*p.PrmPubic, hash.New(), pl)
	if flag1 != true {
		fmt.Println("the fails party is ", p.FromID)
		return
	}
	flag2 := p.ModProof.Verify(*p.ModPubic, hash.New(), pl)
	if flag2 != true {
		fmt.Println("the fails party is ", p.FromID)
		return
	}
	party.Rtig.Add(party.Rtig, p.Rtigi)

}

// 一个开始轮，注意round中network的冗余度为2N
func Round1(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done() //结束繁忙的一轮信息
	//生成随机大数,会话标识符16位应该也可以吧。
	bf := make([]byte, 16)
	rand.Read(bf)
	rtigi := new(big.Int).SetBytes(bf)
	//	fmt.Println(rtig)

	pl := pool.NewPool(0)
	defer pl.TearDown()
	//生成paillier公私钥
	PaillierSecertKey := paillier.NewSecretKey(pl)
	//生成pederson参数
	ped, lambda := PaillierSecertKey.GeneratePedersen()
	//生成prm证明
	public1 := prm.Public{
		N: ped.N(),
		S: ped.S(),
		T: ped.T(),
	}

	Prmproof := prm.NewProof(prm.Private{
		Lambda: lambda,
		Phi:    PaillierSecertKey.Phi(),
		P:      PaillierSecertKey.P(),
		Q:      PaillierSecertKey.Q(),
	}, hash.New(), public1, pl)
	//生成mod证明
	public2 := mod.Public{N: PaillierSecertKey.PublicKey.N()}
	Modproof := mod.NewProof(hash.New(), mod.Private{
		P:   PaillierSecertKey.P(),
		Q:   PaillierSecertKey.Q(),
		Phi: PaillierSecertKey.Phi(),
	}, public2, pl)

	//将信息保存在net.parties上
	party.Rtigi = rtigi
	Rtigi := new(big.Int).SetBytes(bf)
	party.Rtig = Rtigi
	party.PaillierPublickey = PaillierSecertKey.PublicKey
	party.Aux = ped
	//将paillier.secret信息存储下来
	SecretPartInfoi := new(network.SecretPartyInfo)
	SecretPartInfoi.PaillierSecertKey = PaillierSecertKey
	SecretInfo[party.ID] = SecretPartInfoi

	//将生成的rtig，paillierpublic，zkproof保存在待广播的Round1Content上
	Round1Content := Round1Info{party.ID, rtigi, PaillierSecertKey.PublicKey, ped, &public1, Prmproof, &public2, Modproof}

	//本地计算消息位置1，向每一个参与方广播相同消息的时候使用
	Msg := network.Message{FromID: party.ID, ToID: "", MContent: &Round1Content}

	//广播消息
	for _, mparty := range net.Parties {
		//本地计算消息位置2，向每一个参与方广播不同消息使用
		if mparty.ID != party.ID {
			Msg.ToID = mparty.ID
			net.Channels[mparty.ID] <- &Msg
		}
	}
}

//今天就到这里吧，两个问题，信息需要写到party才行。其二。保存私有信息
