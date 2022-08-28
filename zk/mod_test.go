package zk

import (
	"fmt"
	"testing"

	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/zk"
	mod "github.com/taurusgroup/multi-party-sig/pkg/zk/mod"
)

func TestMod(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	p, q := zk.ProverPaillierSecret.P(), zk.ProverPaillierSecret.Q()
	sk := zk.ProverPaillierSecret
	public := mod.Public{N: sk.PublicKey.N()}
	proof := mod.NewProof(hash.New(), mod.Private{
		P:   p,
		Q:   q,
		Phi: sk.Phi(),
	}, public, pl)
	flag := proof.Verify(public, hash.New(), pl)
	fmt.Println(flag)
}
