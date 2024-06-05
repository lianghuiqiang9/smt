package paillier

import (
	"crypto/rand"
	"errors"

	"io"
	"math/big"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

var (
	ErrPaillierLength = errors.New("wrong number bit length of Paillier modulus N")
	ErrPaillierEven   = errors.New("modulus N is even")
	ErrPaillierNil    = errors.New("modulus N is nil")
)

// PublicKey is a Paillier public key. It is represented by a modulus N.
type PublicKey struct {
	// n = p⋅q
	n *arith.Modulus
	// nSquared = n²
	nSquared *arith.Modulus
	//	nn       *safenum.Nat

	// These values are cached out of convenience, and performance
	nNat *safenum.Nat
	// nPlusOne = n + 1
	nPlusOne *safenum.Nat
	//

	Nn       *big.Int // n modulus
	G        *big.Int // n+1, since p and q are same length
	NSquared *big.Int //n^2

}

var One = big.NewInt(1)

func h(p *big.Int, pp *big.Int, n *big.Int) *big.Int {
	gp := new(big.Int).Mod(new(big.Int).Sub(One, n), pp)
	lp := l(gp, p)
	hp := new(big.Int).ModInverse(lp, p)
	return hp
}

func l(u *big.Int, n *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(u, One), n)
}

// N is the public modulus making up this key.
func (pk *PublicKey) N() *safenum.Modulus {
	return pk.n.Modulus
}

// NewPublicKey returns an initialized paillier.PublicKey and caches N, N² and (N-1)/2.
func NewPublicKey(n *safenum.Modulus) *PublicKey {
	OneNat := new(safenum.Nat).SetUint64(1)
	nNat := n.Nat()
	nn := new(safenum.Nat).Mul(nNat, nNat, -1)
	nSquared := safenum.ModulusFromNat(nn)
	nPlusOne := new(safenum.Nat).Add(nNat, OneNat, -1)
	// Tightening is fine, since n is public
	nPlusOne.Resize(nPlusOne.TrueLen())

	Nn := nNat.Big()
	NSquared := nSquared.Big()
	G := nPlusOne.Big()

	return &PublicKey{
		n:        arith.ModulusFromN(n),
		nSquared: arith.ModulusFromN(nSquared),
		nNat:     nNat,
		nPlusOne: nPlusOne,
		Nn:       Nn,
		NSquared: NSquared,
		G:        G,
	}
}

// ValidateN performs basic checks to make sure the modulus is valid:
// - log₂(n) = params.BitsPaillier.
// - n is odd.
func ValidateN(n *safenum.Modulus) error {
	if n == nil {
		return ErrPaillierNil
	}
	// log₂(N) = BitsPaillier
	nBig := n.Big()
	//	if bits := nBig.BitLen(); bits != params.BitsPaillier {
	//		return fmt.Errorf("have: %d, need %d: %w", bits, params.BitsPaillier, ErrPaillierLength)
	//	}
	if nBig.Bit(0) != 1 {
		return ErrPaillierEven
	}
	return nil
}

// Enc returns the encryption of m under the public key pk.
// The nonce used to encrypt is returned.
//
// The message m must be in the range [-(N-1)/2, …, (N-1)/2] and panics otherwise.
//
// ct = (1+N)ᵐρᴺ (mod N²).
func (pk PublicKey) Enc(m *safenum.Int) (*Ciphertext, *safenum.Nat) {
	nonce := sample.UnitModN(rand.Reader, pk.n.Modulus)
	return pk.EncWithNonce(m, nonce), nonce
}

// EncWithNonce returns the encryption of m under the public key pk.
// The nonce is not returned.
//
// The message m must be in the range [-(N-1)/2, …, (N-1)/2] and panics otherwise
//
// ct = (1+N)ᵐρᴺ (mod N²).
func (pk PublicKey) EncWithNonce(m *safenum.Int, nonce *safenum.Nat) *Ciphertext {
	mbig := m.Big()
	r := nonce.Big()
	// c = g^m * r^n mod n^2 = ((m*n+1) mod n^2) * r^n mod n^2
	n := pk.Nn
	cc := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Mod(new(big.Int).Add(One, new(big.Int).Mul(mbig, n)), pk.NSquared),
			new(big.Int).Exp(r, n, pk.NSquared),
		),
		pk.NSquared,
	)
	c := new(safenum.Nat).SetBig(cc, cc.BitLen())
	return &Ciphertext{c: c}
}
func (pk PublicKey) Enc2(m *big.Int) (*Ciphertext, *big.Int) {
	r, err := rand.Int(rand.Reader, pk.Nn)
	if err != nil {
		return nil, nil
	}
	c := pk.EncWithNonce2(m, r)
	if err != nil {
		return nil, nil
	}

	return c, r
}

func (pk PublicKey) EncWithNonce2(m *big.Int, r *big.Int) *Ciphertext {
	// c = g^m * r^n mod n^2 = ((m*n+1) mod n^2) * r^n mod n^2
	n := pk.Nn
	cbig := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Mod(new(big.Int).Add(One, new(big.Int).Mul(m, n)), pk.NSquared),
			new(big.Int).Exp(r, n, pk.NSquared),
		),
		pk.NSquared,
	)
	//	c := new(safenum.Nat).SetBig(cbig, cbig.BitLen())

	return &Ciphertext{cbig: cbig}
}

// Equal returns true if pk ≡ other.
func (pk PublicKey) Equal(other *PublicKey) bool {
	_, eq, _ := pk.n.Cmp(other.n.Modulus)
	return eq == 1
}

// ValidateCiphertexts checks if all ciphertexts are in the correct range and coprime to N²
// ct ∈ [1, …, N²-1] AND GCD(ct,N²) = 1.
func (pk PublicKey) ValidateCiphertexts(cts ...*Ciphertext) bool {
	for _, ct := range cts {
		if ct == nil {
			return false
		}
		_, _, lt := ct.c.CmpMod(pk.nSquared.Modulus)
		if lt != 1 {
			return false
		}
		if ct.c.IsUnit(pk.nSquared.Modulus) != 1 {
			return false
		}
	}
	return true
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (pk *PublicKey) WriteTo(w io.Writer) (int64, error) {
	if pk == nil {
		return 0, io.ErrUnexpectedEOF
	}
	buf := pk.n.Bytes()
	n, err := w.Write(buf)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (PublicKey) Domain() string {
	return "Paillier PublicKey"
}

// Modulus returns an arith.Modulus for N which may allow for accelerated exponentiation when this
// public key was generated from a secret key.
func (pk *PublicKey) Modulus() *arith.Modulus {
	return pk.n
}

// ModulusSquared returns an arith.Modulus for N² which may allow for accelerated exponentiation when this
// public key was generated from a secret key.
func (pk *PublicKey) ModulusSquared() *arith.Modulus {
	return pk.nSquared
}

/*
func (pk *PublicKey) Add2(ct1, ct2 *Ciphertext) *big.Int {
	x := ct1.cbig
	y := ct2.cbig

	// x * y mod n^2
	return new(big.Int).Mod(
		new(big.Int).Mul(x, y),
		pk.NSquared,
	)
}

func (pk *PublicKey) Mul(cipher *Ciphertext, constant *big.Int) *Ciphertext {
	c := cipher.cbig
	x := constant
	// c ^ x mod n^2
	return &Ciphertext{cbig: new(big.Int).Exp(c, x, pk.NSquared)}
}
*/
