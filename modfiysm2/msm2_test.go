package modfiysm2

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"github.com/tjfoc/gmsm/sm2"
)

func TestModfiysm2(t *testing.T) {
	C := sm2.P256Sm2()
	sk, pkx, pky := Generatekey(C, nil)

	fmt.Println(pky.BitLen())

	hash := sha256.New()
	Msg := []byte("HELLO MSM2")
	Z := new(big.Int).SetBytes([]byte{11})

	r, s := Sign(C, hash, Msg, Z, sk, nil)

	MsgTemp := []byte("HELLO MSM2")
	ZTemp := new(big.Int).SetBytes([]byte{11})

	flag := Verify(C, hash, MsgTemp, ZTemp, pkx, pky, r, s)
	fmt.Println("Verfication result : ", flag)

}
