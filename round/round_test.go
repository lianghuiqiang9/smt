package round

import (
	"testing"
	"time"

	"github.com/lianghuiqiang9/smt/network"
)

func TestRound(t *testing.T) {
	//c := sm2.P256Sm2()

	N := 4
	T := 2
	var net = network.NewNetwork(nil, N, T, nil)
	net.Init()

	SecretInfo := make(network.MSecretPartiesInfoMap)

	MRound(StartRound, &net, SecretInfo)

	MRound(Round, &net, SecretInfo)

	MRound(Output, &net, SecretInfo)

	time.Sleep(1 * time.Second)
}
