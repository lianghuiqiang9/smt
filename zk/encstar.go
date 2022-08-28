package zk

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"hash"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
)

type Public struct {
	// Kv is a ciphertext encrypted with Nᵥ
	// Original name: C
	Kv *paillier.Ciphertext

	// Dv = (x ⨀ Kv) ⨁ Encᵥ(y;s)
	Dv *paillier.Ciphertext

	// Fp = Encₚ(y;r)
	// Original name: Y
	Fp *paillier.Ciphertext

	// Xp = gˣ
	Xx *big.Int
	Xy *big.Int

	// Prover = Nₚ
	// Verifier = Nᵥ
	Prover, Verifier *paillier.PublicKey
	Aux              *pedersen.Parameters
}

type Private struct {
	// X = x
	X *safenum.Int
	// Y = y
	Y *safenum.Int
	// S = s
	// Original name: ρ
	S *safenum.Nat
	// R = r
	// Original name: ρy
	R *safenum.Nat
}
type Commitment struct {
	// A = (α ⊙ C) ⊕ Encᵥ(β, ρ)
	A *paillier.Ciphertext
	// Bₓ = α⋅G
	Bxx *big.Int
	Bxy *big.Int
	// By = Encₚ(β, ρy)
	By *paillier.Ciphertext
	// E = sᵃ tᵍ (mod N)
	E *safenum.Nat
	// S = sˣ tᵐ (mod N)
	S *safenum.Nat
	// F = sᵇ tᵈ (mod N)
	F *safenum.Nat
	// T = sʸ tᵘ (mod N)
	T *safenum.Nat
}

type Proof struct {
	curve elliptic.Curve
	*Commitment
	// Z1 = Z₁ = α + e⋅x
	Z1 *safenum.Int
	// Z2 = Z₂ = β + e⋅y
	Z2 *safenum.Int
	// Z3 = Z₃ = γ + e⋅m
	Z3 *safenum.Int
	// Z4 = Z₄ = δ + e⋅μ
	Z4 *safenum.Int
	// W = w = ρ⋅sᵉ (mod N₀)
	W *safenum.Nat
	// Wy = wy = ρy⋅rᵉ (mod N₁)
	Wy *safenum.Nat
}

func (p *Proof) IsValid(public Public) bool {
	if p == nil {
		return false
	}
	if !public.Verifier.ValidateCiphertexts(p.A) {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.By) {
		return false
	}
	if !arith.IsValidNatModN(public.Prover.N(), p.Wy) {
		return false
	}
	if !arith.IsValidNatModN(public.Verifier.N(), p.W) {
		return false
	}
	/*	if p.Bx.IsIdentity() {
		return false
	}*/
	return true
}

func EncstarProof(hash hash.Hash, curve elliptic.Curve, public Public, private Private) *Proof {
	N0 := public.Verifier.N()
	N1 := public.Prover.N()
	N0Modulus := public.Verifier.Modulus()
	N1Modulus := public.Prover.Modulus()

	verifier := public.Verifier
	prover := public.Prover
	//将alpha变为正数
	alpha1 := sample.IntervalLEps(rand.Reader)
	alpha2 := alpha1.Abs()
	alpha := new(safenum.Int).SetNat(alpha2)
	beta := sample.IntervalLPrimeEps(rand.Reader)

	rho := sample.UnitModN(rand.Reader, N0)
	rhoY := sample.UnitModN(rand.Reader, N1)

	gamma := sample.IntervalLEpsN(rand.Reader)
	m := sample.IntervalLN(rand.Reader)
	delta := sample.IntervalLEpsN(rand.Reader)
	mu := sample.IntervalLN(rand.Reader)

	cAlpha := public.Kv.Clone().Mul(verifier, alpha)            // = Cᵃ mod N₀ = α ⊙ Kv
	A := verifier.EncWithNonce(beta, rho).Add(verifier, cAlpha) // = Enc₀(β,ρ) ⊕ (α ⊙ Kv)

	E := public.Aux.Commit(alpha, gamma)
	S := public.Aux.Commit(private.X, m)
	F := public.Aux.Commit(beta, delta)
	T := public.Aux.Commit(private.Y, mu)
	//修改的东西。
	x := alpha.Abs().Big()
	Yx, Yy := curve.ScalarBaseMult(x.Bytes())

	commitment := &Commitment{
		A:   A,
		Bxx: Yx,
		Bxy: Yy,
		By:  prover.EncWithNonce(beta, rhoY),
		E:   E,
		S:   S,
		F:   F,
		T:   T,
	}

	hash.Write(BytesCombine(public.Aux.N().Bytes(), public.Aux.S().Bytes(), public.Aux.T().Bytes(), public.Prover.Modulus().Bytes(), public.Verifier.Modulus().Bytes(), public.Kv.Nat().Bytes(), public.Dv.Nat().Bytes(), public.Fp.Nat().Bytes(), public.Xx.Bytes(), public.Xy.Bytes(), A.Nat().Bytes(), Yx.Bytes(), Yy.Bytes(), commitment.By.Nat().Bytes(), E.Bytes(), S.Bytes(), F.Bytes(), T.Bytes()))
	bytes := hash.Sum(nil)
	e := new(safenum.Int).SetBytes(bytes)
	//注意这里没有控制e的范围，可能会出事请。
	hash.Reset()

	// e•x+α
	z1 := new(safenum.Int).SetInt(private.X)
	z1.Mul(e, z1, -1)
	z1.Add(z1, alpha, -1)
	// e•y+β
	z2 := new(safenum.Int).SetInt(private.Y)
	z2.Mul(e, z2, -1)
	z2.Add(z2, beta, -1)
	// e•m+γ
	z3 := new(safenum.Int).Mul(e, m, -1)
	z3.Add(z3, gamma, -1)
	// e•μ+δ
	z4 := new(safenum.Int).Mul(e, mu, -1)
	z4.Add(z4, delta, -1)
	// ρ⋅sᵉ mod N₀
	w := N0Modulus.ExpI(private.S, e)
	w.ModMul(w, rho, N0)
	// ρy⋅rᵉ  mod N₁
	wY := N1Modulus.ExpI(private.R, e)
	wY.ModMul(wY, rhoY, N1)

	return &Proof{
		curve:      curve,
		Commitment: commitment,
		Z1:         z1,
		Z2:         z2,
		Z3:         z3,
		Z4:         z4,
		W:          w,
		Wy:         wY,
	}
}

func (p Proof) EncstarVerify(hash hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	verifier := public.Verifier
	prover := public.Prover

	if !arith.IsInIntervalLEps(p.Z1) {
		return false
	}
	if !arith.IsInIntervalLPrimeEps(p.Z2) {
		return false
	}

	hash.Write(BytesCombine(public.Aux.N().Bytes(), public.Aux.S().Bytes(), public.Aux.T().Bytes(), public.Prover.Modulus().Bytes(), public.Verifier.Modulus().Bytes(), public.Kv.Nat().Bytes(), public.Dv.Nat().Bytes(), public.Fp.Nat().Bytes(), public.Xx.Bytes(), public.Xy.Bytes(), p.Commitment.A.Nat().Bytes(), p.Commitment.Bxx.Bytes(), p.Commitment.Bxy.Bytes(), p.Commitment.By.Nat().Bytes(), p.Commitment.E.Bytes(), p.Commitment.S.Bytes(), p.Commitment.F.Bytes(), p.Commitment.T.Bytes()))
	bytes := hash.Sum(nil)
	e := new(safenum.Int).SetBytes(bytes)
	//注意这里没有控制e的范围，可能会出事请。
	//	e = (*safenum.Int)(e.Mod(N))
	hash.Reset()

	if !public.Aux.Verify(p.Z1, p.Z3, e, p.E, p.S) {
		return false
	}

	if !public.Aux.Verify(p.Z2, p.Z4, e, p.F, p.T) {
		return false
	}

	{
		// tmp = z₁ ⊙ Kv
		// lhs = Enc₀(z₂;w) ⊕ z₁ ⊙ Kv
		tmp := public.Kv.Clone().Mul(verifier, p.Z1)
		lhs := verifier.EncWithNonce(p.Z2, p.W).Add(verifier, tmp)

		// rhs = (e ⊙ Dv) ⊕ A
		rhs := public.Dv.Clone().Mul(verifier, e).Add(verifier, p.A)

		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		e2 := e.Abs().Big()
		e2.Mod(e2, p.curve.Params().N)
		z := p.Z1.Abs().Big()
		z.Mod(z, p.curve.Params().N)

		zGx, zGy := p.curve.ScalarBaseMult(z.Bytes())
		epkx, epky := p.curve.ScalarMult(public.Xx, public.Xy, e2.Bytes())
		z2Gx, z2Gy := p.curve.Add(p.Commitment.Bxx, p.Commitment.Bxy, epkx, epky)
		ff := zGx.Cmp(z2Gx) == 0 && zGy.Cmp(z2Gy) == 0
		if ff != true {
			return false
		}

	}

	{
		// lhs = Enc₁(z₂; wy)
		lhs := prover.EncWithNonce(p.Z2, p.Wy)

		// rhs = (e ⊙ Fp) ⊕ By
		rhs := public.Fp.Clone().Mul(prover, e).Add(prover, p.By)

		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}
