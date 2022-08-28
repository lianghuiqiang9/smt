package network

import (
	"crypto/elliptic"
	"crypto/sha256"
	"hash"
	"sync"
)

// 定义了一个用户，现在有自己的ID，info,还有一个用户通信表也就是通信录。

type Network struct {
	Parties MParties
	//这里只是定义了管道，还没有定义缓存容量，缓存后面设置了
	Channels map[string]chan *Message
	//用于承诺的HashMap
	Hash hash.Hash
	Mtx  sync.Mutex
	Msg  []byte
}

func NewNetwork(Parties MParties, N, threshold int, curve elliptic.Curve) Network {
	if Parties == nil {
		//显然这里初始化N的时候不能超过26
		//显然这里需要make一个真实的东西。
		Parties = make([]Party, N)
		for i := 0; i < N; i++ {
			Parties[i].Num = i
			Parties[i].ID = string('a' + rune(i))
			Parties[i].N = N
			Parties[i].T = threshold
			Parties[i].Curve = curve
		}
	}
	return Network{
		Parties:  Parties,
		Channels: make(map[string]chan *Message, len(Parties)*2),
		Hash:     sha256.New(),
	}

}
func (n *Network) Init() {
	N := len(n.Parties)
	for _, party := range n.Parties {
		n.Channels[party.ID] = make(chan *Message, N)
	}
}
