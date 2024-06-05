package zk

import (
	"crypto/rand"
	"hash"

	"github.com/cronokirby/safenum"
	"github.com/lianghuiqiang9/smt/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"

	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
)

type Encp struct {
	// S = sᵏtᵘ
	S *safenum.Nat
	// A = Enc₀ (α, r)
	A *paillier.Ciphertext
	// C = sᵃtᵍ
	C *safenum.Nat
	// Z₁ = α + e⋅k
	Z1 *safenum.Int
	// Z₂ = r ⋅ ρᵉ mod N₀
	Z2 *safenum.Nat
	// Z₃ = γ + e⋅μ
	Z3 *safenum.Int
}

// 输入hash, aux, PK,证明的K和k, rho
func EncProve(hash hash.Hash, Aux *pedersen.Parameters, PK *paillier.PublicKey, K *paillier.Ciphertext, k *safenum.Int, rho *safenum.Nat) *Encp {
	N := PK.N()
	NModulus := PK.Modulus()
	alpha := sample.IntervalLEps(rand.Reader)
	r := sample.UnitModN(rand.Reader, N)
	mu := sample.IntervalLN(rand.Reader)
	gamma := sample.IntervalLEpsN(rand.Reader)

	S := Aux.Commit(k, mu)
	A := PK.EncWithNonce(alpha, r)
	C := Aux.Commit(alpha, gamma)

	hash.Write(BytesCombine(Aux.N().Bytes(), Aux.S().Bytes(), Aux.T().Bytes(), PK.Modulus().Bytes(), K.Nat().Bytes(), S.Bytes(), A.Nat().Bytes(), C.Bytes()))
	bytes := hash.Sum(nil)
	e := new(safenum.Int).SetBytes(bytes) //没有控制e的范围

	hash.Reset()

	z1 := new(safenum.Int).SetInt(k)
	z1.Mul(e, z1, -1)
	z1.Add(z1, alpha, -1)

	z2 := NModulus.ExpI(rho, e)
	z2.ModMul(z2, r, N)

	z3 := new(safenum.Int).Mul(e, mu, -1)
	z3.Add(z3, gamma, -1)

	return &Encp{
		S:  S,
		A:  A,
		C:  C,
		Z1: z1,
		Z2: z2,
		Z3: z3,
	}
}

func (zkp *Encp) EncVerify(hash hash.Hash, Aux *pedersen.Parameters, PK *paillier.PublicKey, K *paillier.Ciphertext) bool {
	//缺了范围验证。

	hash.Write(BytesCombine(Aux.N().Bytes(), Aux.S().Bytes(), Aux.T().Bytes(), PK.Modulus().Bytes(), K.Nat().Bytes(), zkp.S.Bytes(), zkp.A.Nat().Bytes(), zkp.C.Bytes()))
	bytes := hash.Sum(nil)
	e := new(safenum.Int).SetBytes(bytes) //没有控制e的范围。
	if !Aux.Verify(zkp.Z1, zkp.Z3, e, zkp.C, zkp.S) {
		return false
	}

	{
		// lhs = Enc(z₁;z₂)
		lhs := PK.EncWithNonce(zkp.Z1, zkp.Z2) //Enc time cost is large

		// rhs = (e ⊙ K) ⊕ A
		rhs := K.Clone().Mul(PK, e).Add(PK, zkp.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}
