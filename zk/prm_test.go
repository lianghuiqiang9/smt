package zk

import (
	"fmt"
	"testing"
	"time"

	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	prm "github.com/taurusgroup/multi-party-sig/pkg/zk/prm"
)

// we do not want to rewrite the prm proof, so we use the taurusgroup, hope that is ok.
func TestPrm(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	sk := paillier.NewSecretKey(pl)
	ped, lambda := sk.GeneratePedersen()

	public := prm.Public{
		N: ped.N(),
		S: ped.S(),
		T: ped.T(),
	}

	start := time.Now()
	proof := prm.NewProof(prm.Private{
		Lambda: lambda,
		Phi:    sk.Phi(),
		P:      sk.P(),
		Q:      sk.Q(),
	}, hash.New(), public, pl)
	flag := proof.Verify(public, hash.New(), pl)
	fmt.Println(flag)
	cost := time.Since(start)
	fmt.Println("prm cost=", cost.Seconds())

}
