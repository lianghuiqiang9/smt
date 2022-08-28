package tskeygen

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/vss"
	"github.com/lianghuiqiang9/smt/zk"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
)

//需要

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

func (p *Round3Info) DoSomething(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	//party是你自己，p是轮流发过来的消息。
	//验证logp
	net.Mtx.Lock()
	flag := p.Round3logp.LogVerify(net.Hash, party.Curve, net.Parties[p.FromNum].Xix, net.Parties[p.FromNum].Xiy)
	net.Mtx.Unlock()
	//	fmt.Println(flag)
	if flag != true {
		fmt.Println("error", p.FromID)
	}
	//关于A,这个又没有广播，所以不在这里做。
	//验证y是否合理。解密yij,注意这里是VssEnci，不是Gi，Gi在MtA里面
	plaintxt, _ := SecretInfo[party.ID].PaillierSecertKey.Dec(p.VssEncyi)
	yij := plaintxt.Big()
	//vssverify
	vss.VssVerify1(p.FromNum, yij, p.VssAx, p.VssAy, party, net, SecretInfo)
	//计算yi
	SecretInfo[party.ID].Y.Add(SecretInfo[party.ID].Y, yij)

	//执行MtA
	//验证logstarp
	net.Mtx.Lock()
	flag2 := p.Round3logstarp.LogstarVerify(net.Hash, net.Parties[p.FromNum].Curve, net.Parties[p.FromNum].Aux, net.Parties[p.FromNum].PaillierPublickey, p.Gi, net.Parties[p.FromNum].Xix, net.Parties[p.FromNum].Xiy)
	net.Mtx.Unlock()
	//	fmt.Println("flag2", flag2)
	if flag2 != true {
		fmt.Println("error", p.FromID)
	}
	//很好，zklog*也都写对了，剩下的就是MtA和Vss合并了。快了，快了。明天说不定就搞完了。
	//反正今天是搞不完了。
	//对Bx，By进行操作
	party.Gammax, party.Gammay = party.Curve.Add(party.Gammax, party.Gammay, p.Bx, p.By)
	//在这里对每一个Gj，将Gj存下来吧。注意要先make一个map
	SecretInfo[party.ID].MtAEncB[p.FromID] = p.Gi
}

func Round3(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()
	//想好了new一个，最后还是没有new，浪费了一个小时
	party.Rho = new(big.Int).Set(SecretInfo[party.ID].Rhoi)

	for i := 0; i < party.N-1; i++ {
		val := <-net.Channels[party.ID] // 出 chan
		val.MContent.DoSomething(party, net, SecretInfo)
	}
	//接下来应该是运行VSS和MultiAdd子协议，在这里为了统一，我们将其放到主协议中。
	party.Xix, party.Xiy = SecretInfo[party.ID].Xix, SecretInfo[party.ID].Xiy
	//广播Gammaix,Gammaiy，自己保存一下Gammaix，Gammaiy
	Bx, By := SecretInfo[party.ID].Gammaix, SecretInfo[party.ID].Gammaiy
	Gammax := new(big.Int).Set(Bx)
	Gammay := new(big.Int).Set(By)
	party.Gammax, party.Gammay = Gammax, Gammay

	Gammaix := new(big.Int).Set(Bx)
	Gammaiy := new(big.Int).Set(By)
	party.Gammaix, party.Gammaiy = Gammaix, Gammaiy

	//不知道自己传的这个指针有没有用
	//	fmt.Println("初始化party公钥X成功", party.ID, SecretInfo[party.ID].Xi)

	vss.Vssshare1(party, net, SecretInfo)

	//生成zklog证明，Xi，是Xix,Xiy的私钥
	//	fmt.Println(party.Num, party.Curve, party.Xix, party.Xiy, SecretInfo[party.ID].Xi)
	net.Mtx.Lock()
	Round3logp := zk.LogProve(net.Hash, party.Curve, party.Xix, party.Xiy, SecretInfo[party.ID].Xi)
	net.Mtx.Unlock()
	//运行MultiAdd协议
	x := new(safenum.Int).SetBig(SecretInfo[party.ID].Xi, SecretInfo[party.ID].Xi.BitLen())
	//	fmt.Println("私钥转换成功", party.ID, SecretInfo[party.ID].Xi, x)
	ct, v := party.PaillierPublickey.Enc(x)
	//未广播的消息尽量还是不要直接放到party里面，免得引起误会。
	SecretInfo[party.ID].EncXi = ct
	//	party.EncXi = ct
	//	fmt.Println("私钥加密成功", party.ID, SecretInfo[party.ID].Xi, ct, v)
	//生成zkencp
	net.Mtx.Lock()
	Round3logstarp := zk.LogstarProve(net.Hash, party.Curve, party.Aux, party.PaillierPublickey, ct, party.Xix, party.Xiy, x, v)
	net.Mtx.Unlock()

	//广播消息位置1

	//广播消息
	for _, mparty := range net.Parties {
		if mparty.ID != party.ID {
			//本地计算消息位置2，向每一个参与方广播不同消息使用

			MRoundContent := Round3Info{party.ID, party.Num, SecretInfo[party.ID].VssEncy[mparty.ID], SecretInfo[party.ID].VssAx, SecretInfo[party.ID].VssAy, Round3logp, Bx, By, ct, Round3logstarp}
			//本地计算消息位置1，向每一个参与方广播相同消息的时候使用
			Msg := network.Message{FromID: party.ID, ToID: "", MContent: &MRoundContent}

			//这里也是单独的情况下

			Msg.ToID = mparty.ID
			net.Channels[mparty.ID] <- &Msg
		}

	}

}
