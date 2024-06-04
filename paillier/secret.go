package paillier

import (
	"crypto/rand"
	"errors"

	"math/big"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

var (
	ErrPrimeBadLength = errors.New("prime factor is not the right length")
	ErrNotBlum        = errors.New("prime factor is not equivalent to 3 (mod 4)")
	ErrNotSafePrime   = errors.New("supposed prime factor is not a safe prime")
	ErrPrimeNil       = errors.New("prime is nil")
)

// SecretKey is the secret key corresponding to a Public Paillier Key.
//
// A public key is a modulus N, and the secret key contains the information
// needed to factor N into two primes, P and Q. This allows us to decrypt
// values encrypted using this modulus.
type SecretKey struct {
	*PublicKey
	// p, q such that N = p⋅q
	p, q *safenum.Nat
	// phi = ϕ = (p-1)(q-1)
	phi *safenum.Nat
	// phiInv = ϕ⁻¹ mod N
	phiInv *safenum.Nat

	p1        *big.Int
	pp        *big.Int
	pminusone *big.Int
	q1        *big.Int
	qq        *big.Int
	qminusone *big.Int
	pinvq     *big.Int
	hp        *big.Int
	hq        *big.Int
	n0        *big.Int
}

func crt(mp *big.Int, mq *big.Int, privKey *SecretKey) *big.Int {
	u := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(mq, mp), privKey.pinvq), privKey.q1)
	m := new(big.Int).Add(mp, new(big.Int).Mul(u, privKey.p1))
	return new(big.Int).Mod(m, privKey.n0)
}

// P returns the first of the two factors composing this key.
func (sk *SecretKey) P() *safenum.Nat {
	return sk.p
}

// Q returns the second of the two factors composing this key.
func (sk *SecretKey) Q() *safenum.Nat {
	return sk.q
}

// Phi returns ϕ = (P-1)(Q-1).
//
// This is the result of the totient function ϕ(N), where N = P⋅Q
// is our public key. This function counts the number of units mod N.
//
// This quantity is useful in ZK proofs.
func (sk *SecretKey) Phi() *safenum.Nat {
	return sk.phi
}

// KeyGen generates a new PublicKey and it's associated SecretKey.
func KeyGen(pl *pool.Pool) (pk *PublicKey, sk *SecretKey) {
	sk = NewSecretKey(pl)
	pk = sk.PublicKey
	return
}

// NewSecretKey generates primes p and q suitable for the scheme, and returns the initialized SecretKey.
func NewSecretKey(pl *pool.Pool) *SecretKey {
	// TODO maybe we could take the reader as argument?
	return NewSecretKeyFromPrimes(sample.Paillier(rand.Reader, pl))
}

// NewSecretKeyFromPrimes generates a new SecretKey. Assumes that P and Q are prime.
func NewSecretKeyFromPrimes(P, Q *safenum.Nat) *SecretKey {
	oneNat := new(safenum.Nat).SetUint64(1)

	n := arith.ModulusFromFactors(P, Q)

	nNat := n.Nat()
	nPlusOne := new(safenum.Nat).Add(nNat, oneNat, -1)
	// Tightening is fine, since n is public
	nPlusOne.Resize(nPlusOne.TrueLen())

	pMinus1 := new(safenum.Nat).Sub(P, oneNat, -1)
	qMinus1 := new(safenum.Nat).Sub(Q, oneNat, -1)
	phi := new(safenum.Nat).Mul(pMinus1, qMinus1, -1)
	// ϕ⁻¹ mod N
	phiInv := new(safenum.Nat).ModInverse(phi, n.Modulus)

	pSquared := pMinus1.Mul(P, P, -1)
	qSquared := qMinus1.Mul(Q, Q, -1)
	nSquared := arith.ModulusFromFactors(pSquared, qSquared)

	n0 := nNat.Big()
	p1 := P.Big()
	q1 := Q.Big()
	pp := pSquared.Big()
	qq := qSquared.Big()

	return &SecretKey{
		p:      P,
		q:      Q,
		phi:    phi,
		phiInv: phiInv,

		p1:        p1,
		pp:        pp,
		pminusone: new(big.Int).Sub(p1, one),
		q1:        q1,
		qq:        qq,
		qminusone: new(big.Int).Sub(q1, one),
		pinvq:     new(big.Int).ModInverse(p1, q1),
		hp:        h(p1, pp, n0),
		hq:        h(q1, qq, n0),
		n0:        n0,

		PublicKey: &PublicKey{
			n:        n,
			nSquared: nSquared,
			nNat:     nNat,
			nPlusOne: nPlusOne,
			Nn:       n0,
			NSquared: new(big.Int).Mul(n0, n0),
			G:        new(big.Int).Add(n0, one), // g = n + 1
		},
	}
}

// Dec decrypts c and returns the plaintext m ∈ ± (N-2)/2.
// It returns an error if gcd(c, N²) != 1 or if c is not in [1, N²-1].
func (sk *SecretKey) Dec(ct *Ciphertext) (*safenum.Int, error) {
	//	oneNat := new(safenum.Nat).SetUint64(1)

	n := sk.PublicKey.n.Modulus

	//区别在这里，所以我认为，这个不能省吧。
	if !sk.PublicKey.ValidateCiphertexts(ct) {
		return nil, errors.New("paillier: failed to decrypt invalid ciphertext")
	}
	//fmt.Println("吃了吗")

	c0 := ct.c.Big()
	cp := new(big.Int).Exp(c0, sk.pminusone, sk.pp)
	lp := l(cp, sk.p1)
	mp := new(big.Int).Mod(new(big.Int).Mul(lp, sk.hp), sk.p1)
	cq := new(big.Int).Exp(c0, sk.qminusone, sk.qq)
	lq := l(cq, sk.q1)

	mqq := new(big.Int).Mul(lq, sk.hq)
	mq := new(big.Int).Mod(mqq, sk.q1)
	m := crt(mp, mq, sk)
	result := new(safenum.Nat).SetBig(m, m.BitLen())

	// see 6.1 https://www.iacr.org/archive/crypto2001/21390136.pdf
	return new(safenum.Int).SetModSymmetric(result, n), nil
}

func (sk *SecretKey) Dec2(ct *Ciphertext) (*big.Int, error) {
	//	oneNat := new(safenum.Nat).SetUint64(1)

	//	n := sk.PublicKey.n.Modulus

	//	if !sk.PublicKey.ValidateCiphertexts(ct) {
	//		return nil, errors.New("paillier: failed to decrypt invalid ciphertext")
	//	}
	c0 := ct.cbig
	cp := new(big.Int).Exp(c0, sk.pminusone, sk.pp)
	lp := l(cp, sk.p1)
	mp := new(big.Int).Mod(new(big.Int).Mul(lp, sk.hp), sk.p1)
	cq := new(big.Int).Exp(c0, sk.qminusone, sk.qq)
	lq := l(cq, sk.q1)

	mqq := new(big.Int).Mul(lq, sk.hq)
	mq := new(big.Int).Mod(mqq, sk.q1)
	m := crt(mp, mq, sk)
	//	result := new(safenum.Nat).SetBig(m, m.BitLen())
	return m, nil
}

// DecWithRandomness returns the underlying plaintext, as well as the randomness used.
func (sk *SecretKey) DecWithRandomness(ct *Ciphertext) (*safenum.Int, *safenum.Nat, error) {
	m, err := sk.Dec(ct)
	if err != nil {
		return nil, nil, err
	}
	mNeg := new(safenum.Int).SetInt(m).Neg(1)

	// x = C(N+1)⁻ᵐ (mod N)
	x := sk.n.ExpI(sk.nPlusOne, mNeg) //有待优化
	x.ModMul(x, ct.c, sk.n.Modulus)

	// r = xⁿ⁻¹ (mod N)
	nInverse := new(safenum.Nat).ModInverse(sk.nNat, safenum.ModulusFromNat(sk.phi))
	r := sk.n.Exp(x, nInverse) //有待优化的
	return m, r, nil
}

func (sk SecretKey) GeneratePedersen() (*pedersen.Parameters, *safenum.Nat) {
	s, t, lambda := sample.Pedersen(rand.Reader, sk.phi, sk.n.Modulus)
	ped := pedersen.New(sk.n, s, t)
	return ped, lambda
}

// ValidatePrime checks whether p is a suitable prime for Paillier.
// Checks:
// - log₂(p) ≡ params.BitsBlumPrime.
// - p ≡ 3 (mod 4).
// - q := (p-1)/2 is prime.
//func ValidatePrime(p *safenum.Nat) error {
//	if p == nil {
//		return ErrPrimeNil
//	}
//	// check bit lengths
//	const bitsWant = params.BitsBlumPrime
//	// Technically, this leaks the number of bits, but this is fine, since returning
//	// an error asserts this number statically, anyways.
//	if bits := p.TrueLen(); bits != bitsWant {
//		return fmt.Errorf("invalid prime size: have: %d, need %d: %w", bits, bitsWant, ErrPrimeBadLength)
//	}
//	// check == 3 (mod 4)
//	if p.Byte(0)&0b11 != 3 {
//		return ErrNotBlum
//	}

//	// check (p-1)/2 is prime
//	pMinus1Div2 := new(safenum.Nat).Rsh(p, 1, -1)

//	if !pMinus1Div2.Big().ProbablyPrime(1) {
//		return ErrNotSafePrime
//	}
//	return nil
//}
