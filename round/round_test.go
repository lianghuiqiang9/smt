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
	var Net = network.NewNetwork(nil, N, T, nil)
	Net.Init()

	SecretInfo := make(network.MSecretPartiesInfoMap)

	MRound(StartRound, &Net, SecretInfo)

	MRound(Round, &Net, SecretInfo)

	MRound(Output, &Net, SecretInfo)

	time.Sleep(1 * time.Second)
}
