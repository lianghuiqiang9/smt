package network

import (
	"fmt"
	"testing"
	"time"
)

func TestNetwork(t *testing.T) {

	fmt.Println("test start")
	N := 4
	T := 2
	var Net = NewNetwork(nil, N, T, nil)

	Net.Init()

	go func() {
		for _, id := range Net.Parties {
			Net.Channels[id.ID] <- &Message{"a", id.ID, nil}

		}
	}()
	for _, id := range Net.Parties {
		value, err := <-Net.Channels[id.ID]
		if !err {
			fmt.Println("read message fails")
		}
		fmt.Println(value)
	}

	time.Sleep(1 * time.Second)

	go func() {
		for _, id := range Net.Parties {

			Net.Channels["a"] <- &Message{id.ID, "a", nil}

		}
	}()

	go func() {
		for {
			val := <-Net.Channels["a"] // 出 chan
			fmt.Println(val)
		}
	}()

	time.Sleep(1 * time.Second)
	fmt.Println("test end")

}
