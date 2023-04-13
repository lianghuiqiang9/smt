package zk

import (
	//	"crypto/rand"
	"fmt"
	"testing"
	"time"

	//	paillierbig "github.com/roasbeef/go-go-gadget-paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	prm "github.com/taurusgroup/multi-party-sig/pkg/zk/prm"
)

func TestPrm(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	//	paillierprivkey, _ := paillierbig.GenerateKey(rand.Reader, 2048)
	//	paillierpubkey := paillierprivkey.PublicKey

	//		SecretInfoi.PaillierSecertKey = paillierSecret
	//SecretInfoi.Paillierprivkey = paillierprivkey

	sk := paillier.NewSecretKey(pl)
	ped, lambda := sk.GeneratePedersen()

	public := prm.Public{
		N: ped.N(),
		S: ped.S(),
		T: ped.T(),
	}

	start1 := time.Now()
	proof := prm.NewProof(prm.Private{
		Lambda: lambda,
		Phi:    sk.Phi(),
		P:      sk.P(),
		Q:      sk.Q(),
	}, hash.New(), public, pl)
	flag := proof.Verify(public, hash.New(), pl)
	fmt.Println(flag)
	cost1 := time.Since(start1)
	fmt.Println("prm cost=", cost1.Seconds())

}
