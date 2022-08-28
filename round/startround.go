package round

import (
	"fmt"
	"sync"

	"github.com/lianghuiqiang9/smt/network"
)

type StartRoundContent struct {
	MRoundNumber int
	Minfo        int
	Num          int
}

// 定义的每一个Content都要有一个这样的方法来引入，方便万能指针指向
func (p *StartRoundContent) DoSomething(party *network.Party, net *network.Network, SecertInfo network.MSecretPartiesInfoMap) {
	fmt.Println("this is the Round number ", p.MRoundNumber)
}

// 一个开始轮，注意round中network的冗余度为2N
func StartRound(party *network.Party, net *network.Network, SecertInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done() //结束繁忙的一轮信息

	MStartRoundContent := StartRoundContent{0, 1, 1}

	//本地计算消息位置1，向每一个参与方广播相同消息的时候使用
	Msg := network.Message{FromID: "a", ToID: "", MContent: &MStartRoundContent}

	//广播消息
	for _, mparty := range net.Parties {
		//本地计算消息位置2，向每一个参与方广播不同消息使用
		if mparty.ID != party.ID {
			net.Channels[mparty.ID] <- &Msg
		}
	}
}
