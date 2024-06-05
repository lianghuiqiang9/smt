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
	//如何计算Z？？？，Rtig,Rho,Xx,Xy,G。
	//先这样计算吧。反正都一样的。

	//设置签名消息
	msg := Net.Msg
	Net.Mtx.Lock()
	//计算Z
	Net.Hash.Write(zk.BytesCombine(party.Rtig.Bytes(), party.Rho.Bytes(), party.Xx.Bytes(), party.Xy.Bytes()))
	bytes := Net.Hash.Sum(nil)
	//将hash映射到椭圆曲线阶上。
	Z := new(big.Int).SetBytes(bytes)
	Net.Hash.Reset()

	//计算e
	Net.Hash.Write(zk.BytesCombine(Z.Bytes(), msg))
	bytes2 := Net.Hash.Sum(nil)
	//将hash映射到椭圆曲线阶上。
	e := new(big.Int).SetBytes(bytes2)

	Net.Hash.Reset()
	Net.Mtx.Unlock()

	//计算r
	e.Add(e, party.Rx)
	r := new(big.Int).Mod(e, party.Curve.Params().N)

	party.R = r

	//计算s
	s := new(big.Int).Mul(SecretInfo[party.ID].Wi, r)
	s.Mod(s, party.Curve.Params().N)
	s.Add(s, SecretInfo[party.ID].Chi)
	s.Mod(s, party.Curve.Params().N)
	SecretInfo[party.ID].S = s

	Round1Content := Round1Info{party.ID, party.Num, s}
	Msg := network.Message{FromID: party.ID, ToID: "", MContent: &Round1Content}

	//广播消息,不失去一般性，这里只考虑前T个参与方
	for i := 0; i < party.T; i++ {
		if Net.Parties[i].ID != party.ID {
			Msg.ToID = Net.Parties[i].ID
			Net.Channels[Net.Parties[i].ID] <- &Msg
		}
	}
}
