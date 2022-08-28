package curve

import (
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/cronokirby/safenum"
	sm2 "github.com/tjfoc/gmsm/sm2"
)

func TestCurve(t *testing.T) {

	//这里主要用于调试公钥和sm2曲线的一些基本操作。有一个问题就是P+P=0，但是2P是正确的

	priv, _ := sm2.GenerateKey()

	n := priv.Params().N
	fmt.Println(n, reflect.TypeOf(n))
	//得到基点
	Gx, Gy := priv.Curve.Params().Gx, priv.Curve.Params().Gy
	fmt.Println(Gx, Gy, reflect.TypeOf(Gx))

	//得到公钥x,y
	x, y := priv.X, priv.Y
	fmt.Println("PK", x, y, reflect.TypeOf(x), reflect.TypeOf(y))

	//得到私钥
	sk := priv.D
	fmt.Println(sk, reflect.TypeOf(sk))
	//计算skG
	Grx1, Gry1 := priv.ScalarMult(Gx, Gy, sk.Bytes())
	fmt.Println("skG", Grx1, Gry1, reflect.TypeOf(Grx1))

	//计算点乘
	d := []byte{2}
	rx, ry := priv.Curve.ScalarBaseMult(d)
	fmt.Println(rx, ry, reflect.TypeOf(ry))
	fmt.Println("*************")

	//大数相加Add，模Mod
	var x3, y3 = x, y
	x3.Add(x3, x3)
	x3.Mod(x3, n)
	y3.Add(y3, y3)
	y3.Mod(y3, n)
	fmt.Println(x3, y3, reflect.TypeOf(x3), reflect.TypeOf(y3))

	dd := []byte{11}
	fmt.Println(d)
	bigd := new(big.Int).SetBytes(dd)
	fmt.Println(bigd)
	//将big变为safenum
	safed := new(safenum.Nat).SetBig(bigd, bigd.BitLen())
	fmt.Println(safed)
	fmt.Println(14 + 13*16 + 15*16*16 + 6*16*16*16)

	//将safenum变为big
	big2d := safed.Big()
	fmt.Println(big2d)

	//ok，这里也有字符串变成大数的了。现在一切都准备就绪了。
	big3d, _ := new(big.Int).SetString("2862345635245435645324338", 0)
	fmt.Println(big3d)

}
