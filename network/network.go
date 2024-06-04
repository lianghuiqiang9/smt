package network

import (
	"crypto/elliptic"
	"crypto/sha256"
	"hash"
	"sync"
)

type Network struct {
	Parties  MParties
	Channels map[string]chan *Message
	Hash     hash.Hash
	Mtx      sync.Mutex
	Msg      []byte
}

func NewNetwork(Parties MParties, N, threshold int, curve elliptic.Curve) Network {
	if Parties == nil {
		//N<26 because a-z

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
func (net *Network) Init() {
	N := len(net.Parties)
	for _, party := range net.Parties {
		net.Channels[party.ID] = make(chan *Message, N)
	}
}
