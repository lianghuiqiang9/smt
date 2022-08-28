package network

import (
	"fmt"
	"testing"
	"time"

	"github.com/tjfoc/gmsm/sm2"
)

func TestNetwork(t *testing.T) {
	c := sm2.P256Sm2()
	N := 4
	Threshold := 2
	var net = NewNetwork(nil, N, Threshold, c)

	net.Init()

	go func() {
		for _, id := range net.Parties {
			net.Channels[id.ID] <- &Message{"a", id.ID, nil}

		}
	}()
	for _, id := range net.Parties {
		value, err := <-net.Channels[id.ID]
		if !err {
			fmt.Println("read message fails")
		}
		fmt.Println(value)
	}

	time.Sleep(1 * time.Second)

	go func() {
		for _, id := range net.Parties {

			net.Channels["a"] <- &Message{id.ID, "a", nil}

		}
	}()

	go func() {
		for {
			val := <-net.Channels["a"] // 出 chan
			fmt.Println(val)
		}
	}()

	time.Sleep(1 * time.Second)
	fmt.Println("main end")

}
