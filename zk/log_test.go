package zk

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/tjfoc/gmsm/sm2"
)

func TestLog(t *testing.T) {
	priv, _ := sm2.GenerateKey()

	hash := sha256.New()

	logp := LogProve(hash, priv.Curve, priv.X, priv.Y, priv.D)

	flag := logp.LogVerify(hash, priv.Curve, priv.X, priv.Y)
	fmt.Println(flag)
}
