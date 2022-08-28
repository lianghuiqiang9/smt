package zk

import (
	"crypto/sha256"
	"fmt"
	"testing"

	msm2 "github.com/lianghuiqiang9/smt/modfiysm2"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/zk"
	"github.com/tjfoc/gmsm/sm2"
)

func TestLogstar(t *testing.T) {
	//初始化参数，设置Aux，paillier，和Curve
	Aux := zk.Pedersen
	p, _ := new(safenum.Nat).SetHex("FD90167F42443623D284EA828FB13E374CBF73E16CC6755422B97640AB7FC77FDAF452B4F3A2E8472614EEE11CC8EAF48783CE2B4876A3BB72E9ACF248E86DAA5CE4D5A88E77352BCBA30A998CD8B0AD2414D43222E3BA56D82523E2073730F817695B34A4A26128D5E030A7307D3D04456DC512EBB8B53FDBD1DFC07662099B")
	q, _ := new(safenum.Nat).SetHex("DB531C32024A262A0DF9603E48C79E863F9539A82B8619480289EC38C3664CC63E3AC2C04888827559FFDBCB735A8D2F1D24BAF910643CE819452D95CAFFB686E6110057985E93605DE89E33B99C34140EF362117F975A5056BFF14A51C9CD16A4961BE1F02C081C7AD8B2A5450858023A157AFA3C3441E8E00941F8D33ED6B7")
	paillierSecret := paillier.NewSecretKeyFromPrimes(p, q)
	paillierPublic := paillierSecret.PublicKey
	priv, _ := sm2.GenerateKey()

	xi, _ := msm2.RandFieldElement(priv.Curve, nil)
	x := new(safenum.Int).SetBig(xi, xi.BitLen())
	ct, rho := paillierPublic.Enc(x)
	Xx, Xy := priv.Curve.ScalarBaseMult(xi.Bytes())

	hash := sha256.New()
	encp := LogstarProve(hash, priv.Curve, Aux, paillierPublic, ct, Xx, Xy, x, rho)

	flag := encp.LogstarVerify(hash, priv.Curve, Aux, paillierPublic, ct, Xx, Xy)
	fmt.Println("flag", flag)

}
