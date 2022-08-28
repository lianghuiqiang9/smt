package network

import "fmt"

type Message struct {
	FromID   string
	ToID     string
	MContent Content
}

// 定义了一个message的方法
func (msg *Message) Printfid() {
	fmt.Println("this is the id ", msg.FromID)
}

// 定义了一个接口，用来实现message的多态性。
type Msg interface {
	Printfid()
}
type Content interface {
	DoSomething(*Party, *Network, MSecretPartiesInfoMap)
}
