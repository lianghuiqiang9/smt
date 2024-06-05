package curve

import (
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/cronokirby/safenum"
	"github.com/tjfoc/gmsm/sm2"
)

func TestCurve(t *testing.T) {

	priv, _ := sm2.GenerateKey()

	n := priv.Params().N
	fmt.Println("n : ", n, reflect.TypeOf(n))

	Gx, Gy := priv.Curve.Params().Gx, priv.Curve.Params().Gy
	fmt.Println("G : ", Gx, Gy, reflect.TypeOf(Gx))

	pkx, pky := priv.X, priv.Y
	fmt.Println("PK : ", pkx, pky, reflect.TypeOf(pkx), reflect.TypeOf(pky))

	sk := priv.D
	fmt.Println("sk : ", sk, reflect.TypeOf(sk))

	skGx, skGy := priv.ScalarMult(Gx, Gy, sk.Bytes())
	fmt.Println("skG : ", skGx, skGy, reflect.TypeOf(skGx), reflect.TypeOf(skGy))

	if skGx.Cmp(pkx) != 0 || skGy.Cmp(pky) != 0 {
		fmt.Println("Error in pk")
	} else {
		fmt.Println("Correct in pk")
	}

	d := []byte{2}
	dGx, dGy := priv.Curve.ScalarBaseMult(d)
	fmt.Println("dG : ", dGx, dGy, reflect.TypeOf(dGx), reflect.TypeOf(dGy))

	DoubleGx, DoubleGy := priv.Curve.Add(Gx, Gy, Gx, Gy)
	fmt.Println("DoubleG : ", DoubleGx, DoubleGy, reflect.TypeOf(DoubleGx), reflect.TypeOf(DoubleGy))

	if dGx.Cmp(DoubleGx) != 0 || dGy.Cmp(DoubleGy) != 0 {
		fmt.Println("Error in 2*G")
	} else {
		fmt.Println("Correct in 2*G")
	}

	var x, y = Gx, Gy
	x.Add(x, x)
	x.Mod(x, n)
	y.Add(y, y)
	y.Mod(y, n)
	fmt.Println("x, y : ", x, y, reflect.TypeOf(x), reflect.TypeOf(y))

	z := []byte{11}
	fmt.Println("z : ", z)
	zBig := new(big.Int).SetBytes(z)
	fmt.Println("zBig : ", zBig)

	zSafe := new(safenum.Nat).SetBig(zBig, zBig.BitLen())
	fmt.Println("zSafe : ", zSafe)

	zSafeToBig := zSafe.Big()
	fmt.Println("zSafeToBig : ", zSafeToBig)

	BigFromStr, _ := new(big.Int).SetString("2862345635245435645324338", 0)
	fmt.Println("BigFromStr : ", BigFromStr)

}
