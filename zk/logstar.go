package zk

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/cronokirby/safenum"
	"github.com/lianghuiqiang9/smt/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
	"hash"
	"math/big"
)

type Logstarp struct {
	// S = sᵏtᵘ
	S *safenum.Nat
	// A = Enc₀ (α, r)
	A *paillier.Ciphertext
	// C = sᵃtᵍ
	C  *safenum.Nat
	Yx *big.Int
	Yy *big.Int
	// Z₁ = α + e⋅k
	Z1 *safenum.Int
	// Z₂ = r ⋅ ρᵉ mod N₀
	Z2 *safenum.Nat
	// Z₃ = γ + e⋅μ
	Z3 *safenum.Int
}

func LogstarProve(hash hash.Hash, curve elliptic.Curve, Aux *pedersen.Parameters, PK *paillier.PublicKey, K *paillier.Ciphertext, Xx *big.Int, Xy *big.Int, k *safenum.Int, rho *safenum.Nat) *Logstarp {
	N := PK.N()
	NModulus := PK.Modulus()
	//Let alpha be a positive number.
	alpha1 := sample.IntervalLEps(rand.Reader)
	alpha2 := alpha1.Abs()
	alpha := new(safenum.Int).SetNat(alpha2)

	r := sample.UnitModN(rand.Reader, N)
	mu := sample.IntervalLN(rand.Reader)
	gamma := sample.IntervalLEpsN(rand.Reader)

	S := Aux.Commit(k, mu)
	A := PK.EncWithNonce(alpha, r)
	C := Aux.Commit(alpha, gamma)
	x := alpha.Abs().Big()
	Yx, Yy := curve.ScalarBaseMult(x.Bytes())

	hash.Write(BytesCombine(Aux.N().Bytes(), Aux.S().Bytes(), Aux.T().Bytes(), PK.Modulus().Bytes(), K.Nat().Bytes(), S.Bytes(), A.Nat().Bytes(), C.Bytes(), Yx.Bytes(), Yy.Bytes()))
	bytes := hash.Sum(nil)
	e := new(safenum.Int).SetBytes(bytes) //Lack of scope for control e
	hash.Reset()

	z1 := new(safenum.Int).SetInt(k)
	z1.Mul(e, z1, -1)
	z1.Add(z1, alpha, -1)

	z2 := NModulus.ExpI(rho, e)
	z2.ModMul(z2, r, N)

	z3 := new(safenum.Int).Mul(e, mu, -1)
	z3.Add(z3, gamma, -1)

	return &Logstarp{
		S:  S,
		A:  A,
		C:  C,
		Yx: Yx,
		Yy: Yy,
		Z1: z1,
		Z2: z2,
		Z3: z3,
	}
}

func (zkp *Logstarp) LogstarVerify(hash hash.Hash, curve elliptic.Curve, Aux *pedersen.Parameters, PK *paillier.PublicKey, K *paillier.Ciphertext, Xx *big.Int, Xy *big.Int) bool {
	//Lack of scope validation.

	hash.Write(BytesCombine(Aux.N().Bytes(), Aux.S().Bytes(), Aux.T().Bytes(), PK.Modulus().Bytes(), K.Nat().Bytes(), zkp.S.Bytes(), zkp.A.Nat().Bytes(), zkp.C.Bytes(), zkp.Yx.Bytes(), zkp.Yy.Bytes()))
	bytes := hash.Sum(nil)
	hash.Reset()
	e := new(safenum.Int).SetBytes(bytes) //Lack of scope for control e

	if !Aux.Verify(zkp.Z1, zkp.Z3, e, zkp.C, zkp.S) {
		return false
	}

	{
		// lhs = Enc(z₁;z₂)
		lhs := PK.EncWithNonce(zkp.Z1, zkp.Z2)

		// rhs = (e ⊙ K) ⊕ A
		rhs := K.Clone().Mul(PK, e).Add(PK, zkp.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}
	//	zkp.Z1.Abs()
	e2 := e.Abs().Big()
	e2.Mod(e2, curve.Params().N)
	z := zkp.Z1.Abs().Big()
	z.Mod(z, curve.Params().N)

	zGx, zGy := curve.ScalarBaseMult(z.Bytes())
	epkx, epky := curve.ScalarMult(Xx, Xy, e2.Bytes())
	z2Gx, z2Gy := curve.Add(zkp.Yx, zkp.Yy, epkx, epky)

	return zGx.Cmp(z2Gx) == 0 && zGy.Cmp(z2Gy) == 0
}
