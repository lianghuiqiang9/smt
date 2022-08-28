package modfiysm2

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"github.com/tjfoc/gmsm/sm2"
)

func TestModfiysm2(t *testing.T) {
	//选定初始化曲线
	C := sm2.P256Sm2()
	//sk作为私钥
	sk, pkx, pky := Generatekey(C, nil)

	fmt.Println(pky.BitLen())

	hash := sha256.New()
	msg := []byte("HELLO MSM2")

	r, s := Sign(C, hash, msg, sk, nil)

	msg2 := []byte("HELLO MSM2")
	Z := new(big.Int)

	flag := Verify(C, hash, msg2, Z, pkx, pky, r, s)
	fmt.Println("签名验证结果", flag)

}
