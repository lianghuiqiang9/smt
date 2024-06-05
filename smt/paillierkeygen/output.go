package paillierkeygen

import (
	"sync"

	"github.com/lianghuiqiang9/smt/network"
)

func Output(party *network.Party, Net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()

	//本地接受消息,刚才是每一个人往party里面放了一个msg，现在开始读取这个消息，验证每一个人
	//验证每一个人发送的消息是否是正确的。
	for i := 0; i < party.N-1; i++ {
		val := <-Net.Channels[party.ID] // 出 chan
		//	fmt.Println(party.ID, i)
		//现在的问题是，你传进去的是一个，万能指针，但是又不能对messag里面的content进行操作。
		//就是对于每一个消息，这个线程的party对这个msg进行的处理。
		val.MContent.DoSomething(party, Net, SecretInfo)

		//本地计算消息
	}
}
