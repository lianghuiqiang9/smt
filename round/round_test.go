package round

import (
	"fmt"
	"testing"
	"time"

	"github.com/lianghuiqiang9/smt/network"

	"github.com/tjfoc/gmsm/sm2"
)

func TestRound(t *testing.T) {
	c := sm2.P256Sm2()

	//可以初始化Parties，也可以不初始化吧。
	N := 4
	T := 2
	var net = network.NewNetwork(nil, N, T, c)
	net.Init()

	SecretInfo := make(network.MSecretPartiesInfoMap)

	MRound(StartRound, &net, SecretInfo)

	MRound(Round, &net, SecretInfo)

	MRound(Output, &net, SecretInfo)
	//在这里，如果自递归的话，会更加的简洁。

	time.Sleep(1 * time.Second)
	fmt.Println("main end")
}

//写了两天，再回头看，都有点看不懂了，搞笑搞笑。
