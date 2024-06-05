package paillier

import (
	"crypto/rand"
	"fmt"
	"testing"
	"testing/quick"
	"time"

	"github.com/cronokirby/safenum"
	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

var (
	paillierPublic *PublicKey
	paillierSecret *SecretKey
)

func reinit() {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	paillierPublic, paillierSecret = KeyGen(pl)
}

func TestCiphertextValidate(t *testing.T) {
	if !testing.Short() {
		reinit()
	}
	C := new(safenum.Nat)
	Cbig := C.Big()
	ct := &Ciphertext{C, Cbig}
	_, err := paillierSecret.Dec(ct)
	assert.Error(t, err, "decrypting 0 should fail")

	C.SetNat(paillierPublic.nNat)
	_, err = paillierSecret.Dec(ct)
	assert.Error(t, err, "decrypting N should fail")

	C.Add(C, C, -1)
	_, err = paillierSecret.Dec(ct)
	assert.Error(t, err, "decrypting 2N should fail")

	C.SetNat(paillierPublic.nSquared.Nat())
	_, err = paillierSecret.Dec(ct)
	assert.Error(t, err, "decrypting N^2 should fail")
}

func TestIsok(t *testing.T) {
	p, _ := new(safenum.Nat).SetHex("FD90167F42443623D284EA828FB13E374CBF73E16CC6755422B97640AB7FC77FDAF452B4F3A2E8472614EEE11CC8EAF48783CE2B4876A3BB72E9ACF248E86DAA5CE4D5A88E77352BCBA30A998CD8B0AD2414D43222E3BA56D82523E2073730F817695B34A4A26128D5E030A7307D3D04456DC512EBB8B53FDBD1DFC07662099B")
	q, _ := new(safenum.Nat).SetHex("DB531C32024A262A0DF9603E48C79E863F9539A82B8619480289EC38C3664CC63E3AC2C04888827559FFDBCB735A8D2F1D24BAF910643CE819452D95CAFFB686E6110057985E93605DE89E33B99C34140EF362117F975A5056BFF14A51C9CD16A4961BE1F02C081C7AD8B2A5450858023A157AFA3C3441E8E00941F8D33ED6B7")
	paillierSecret = NewSecretKeyFromPrimes(p, q)
	paillierPublic = paillierSecret.PublicKey

	pSafe := new(safenum.Int).SetNat(p)
	start := time.Now()
	ctpSafe, _ := paillierPublic.Enc(pSafe)
	cost := time.Since(start)
	fmt.Println("Enc cost =", cost.Seconds())
	pBig := p.Big()
	start = time.Now()
	ctpBig, _ := paillierPublic.Enc2(pBig)
	cost = time.Since(start)
	fmt.Println("Enc2 cost=", cost.Seconds())

	start = time.Now()
	_, _ = paillierSecret.Dec(ctpSafe)
	cost = time.Since(start)
	fmt.Println("Dec cost =", cost.Seconds())
	start = time.Now()
	_, _ = paillierSecret.Dec2(ctpBig)
	cost = time.Since(start)
	fmt.Println("Dec2 cost=", cost.Seconds())

	start = time.Now()
	_ = ctpSafe.Add(paillierPublic, ctpSafe)
	cost = time.Since(start)
	fmt.Println("Add cost =", cost.Seconds())

	ctpSafe.cbig = ctpSafe.c.Big()
	start = time.Now()
	_ = ctpSafe.Add2(paillierPublic, ctpSafe)
	cost = time.Since(start)
	fmt.Println("Add2 cost=", cost.Seconds())

	pBigSafe := new(safenum.Int).SetBig(pBig, pBig.BitLen())
	start = time.Now()
	_ = ctpSafe.Mul(paillierPublic, pBigSafe)
	cost = time.Since(start)
	fmt.Println("Mul cost =", cost.Seconds())

	start = time.Now()
	_ = ctpSafe.Mul2(paillierPublic, pBig)
	cost = time.Since(start)
	fmt.Println("Mul2 cost=", cost.Seconds())

}

func testEncDecRoundTrip(x uint64, xNeg bool) bool {
	m := new(safenum.Int).SetUint64(x)
	if xNeg {
		m.Neg(1)
	}
	ciphertext, _ := paillierPublic.Enc(m)
	shouldBeM, err := paillierSecret.Dec(ciphertext)
	if err != nil {
		return false
	}
	return m.Eq(shouldBeM) == 1
}

func TestEncDecRoundTrip(t *testing.T) {
	if !testing.Short() {
		reinit()
	}
	err := quick.Check(testEncDecRoundTrip, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}

func testEncDecHomomorphic(a, b uint64, aNeg, bNeg bool) bool {
	ma := new(safenum.Int).SetUint64(a)
	if aNeg {
		ma.Neg(1)
	}
	mb := new(safenum.Int).SetUint64(b)
	if bNeg {
		mb.Neg(1)
	}
	ca, _ := paillierPublic.Enc(ma)
	cb, _ := paillierPublic.Enc(mb)
	expected := new(safenum.Int).Add(ma, mb, -1)
	actual, err := paillierSecret.Dec(ca.Add(paillierPublic, cb))
	if err != nil {
		return false
	}
	return actual.Eq(expected) == 1
}

func TestEncDecHomomorphic(t *testing.T) {
	if !testing.Short() {
		reinit()
	}
	err := quick.Check(testEncDecHomomorphic, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}

func testEncDecScalingHomomorphic(s, x uint64, sNeg, xNeg bool) bool {
	m := new(safenum.Int).SetUint64(x)
	if xNeg {
		m.Neg(1)
	}
	sInt := new(safenum.Int).SetUint64(s)
	if sNeg {
		sInt.Neg(1)
	}
	c, _ := paillierPublic.Enc(m)
	expected := new(safenum.Int).Mul(m, sInt, -1)
	actual, err := paillierSecret.Dec(c.Mul(paillierPublic, sInt))
	if err != nil {
		return false
	}
	return actual.Eq(expected) == 1
}

func TestEncDecScalingHomomorphic(t *testing.T) {
	if !testing.Short() {
		reinit()
	}
	err := quick.Check(testEncDecScalingHomomorphic, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}

func testDecWithRandomness(x, r uint64) bool {
	mExpected := new(safenum.Int).SetUint64(x)
	nonceExpected := new(safenum.Nat).SetUint64(r)
	c := paillierPublic.EncWithNonce(mExpected, nonceExpected)
	mActual, nonceActual, err := paillierSecret.DecWithRandomness(c)
	if err != nil {
		return false
	}
	if mActual.Eq(mExpected) != 1 {
		return false
	}
	if nonceActual.Eq(nonceExpected) != 1 {
		return false
	}
	return true
}

func TestDecWithRandomness(t *testing.T) {
	if !testing.Short() {
		reinit()
	}
	err := quick.Check(testDecWithRandomness, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}

// Used to avoid benchmark optimization.
var resultCiphertext *Ciphertext

func BenchmarkEncryption(b *testing.B) {
	b.StopTimer()
	m := sample.IntervalLEps(rand.Reader)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		resultCiphertext, _ = paillierPublic.Enc(m)
	}
}

func BenchmarkAddCiphertext(b *testing.B) {
	b.StopTimer()
	m := sample.IntervalLEps(rand.Reader)
	c, _ := paillierPublic.Enc(m)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		resultCiphertext = c.Add(paillierPublic, c)
	}
}

func BenchmarkMulCiphertext(b *testing.B) {
	b.StopTimer()
	m := sample.IntervalLEps(rand.Reader)
	c, _ := paillierPublic.Enc(m)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		resultCiphertext = c.Mul(paillierPublic, m)
	}
}
