package zk

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	msm2 "github.com/lianghuiqiang9/smt/modfiysm2"

	"github.com/cronokirby/safenum"

	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	mzk "github.com/taurusgroup/multi-party-sig/pkg/zk"
	"github.com/tjfoc/gmsm/sm2"
)

func TestEncstar(t *testing.T) {

	priv, _ := sm2.GenerateKey()

	xi, _ := msm2.RandFieldElement(priv.Curve, nil)

	x := new(safenum.Int).SetBig(xi, xi.BitLen())

	Xx, Xy := priv.Curve.ScalarBaseMult(xi.Bytes())

	verifierPaillier := mzk.VerifierPaillierPublic
	verifierPedersen := mzk.Pedersen
	prover := mzk.ProverPaillierPublic

	c := new(safenum.Int).SetUint64(12)
	C, _ := verifierPaillier.Enc(c)

	y := sample.IntervalLPrime(rand.Reader)
	Y, rhoY := prover.Enc(y)

	tmp := C.Clone().Mul(verifierPaillier, x)
	D, rho := verifierPaillier.Enc(y)
	D.Add(verifierPaillier, tmp)

	public := Public{
		Kv:       C,
		Dv:       D,
		Fp:       Y,
		Xx:       Xx,
		Xy:       Xy,
		Prover:   prover,
		Verifier: verifierPaillier,
		Aux:      verifierPedersen,
	}
	private := Private{
		X: x,
		Y: y,
		S: rho,
		R: rhoY,
	}
	hash := sha256.New()
	proof := EncstarProof(hash, priv.Curve, public, private)

	flag := proof.EncstarVerify(hash, public)
	fmt.Println("flag ", flag)

}
