package network

import "fmt"

type Message struct {
	FromID   string
	ToID     string
	MContent Content
}

func (msg *Message) Printfid() {
	fmt.Println("this is the id ", msg.FromID)
}

type Msg interface {
	Printfid()
}
type Content interface {
	DoSomething(*Party, *Network, MSecretPartiesInfoMap)
}
