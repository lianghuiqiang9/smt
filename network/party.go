package network

import (
	"crypto/elliptic"
	"math/big"

	"github.com/lianghuiqiang9/smt/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
)

type Bytes []byte

type Party struct {
	Num   int
	ID    string
	N     int
	T     int
	Curve elliptic.Curve
	Rtigi *big.Int
	Rtig  *big.Int

	PaillierPublickey *paillier.PublicKey

	Aux *pedersen.Parameters
	Rho *big.Int
	Xx  *big.Int
	Xy  *big.Int
	Xix *big.Int
	Xiy *big.Int
	Yix *big.Int
	Yiy *big.Int

	EncXi *paillier.Ciphertext

	Gammaix *big.Int
	Gammaiy *big.Int
	Gammax  *big.Int
	Gammay  *big.Int
	Delta   *big.Int
	Deltax  *big.Int
	Deltay  *big.Int
	Ax      *big.Int
	Ay      *big.Int
	Rx      *big.Int
	Ry      *big.Int
	Rix     *big.Int
	Riy     *big.Int

	EncWi *paillier.Ciphertext

	R *big.Int
	S *big.Int
}
type MParties []Party

type SecretPartyInfo struct {
	//main info
	PaillierSecertKey *paillier.SecretKey
	X                 *big.Int
	Y                 *big.Int
	Wi                *big.Int
	Chi               *big.Int

	//temp info
	Xi      *big.Int
	Gammai  *big.Int
	Xix     *big.Int
	Xiy     *big.Int
	Gammaix *big.Int
	Gammaiy *big.Int
	Rhoi    *big.Int
	Ui      *big.Int
	V       map[string]*big.Int

	//VSS info, Round3
	Vssa  map[int]*big.Int
	VssAx map[int]*big.Int
	VssAy map[int]*big.Int
	Vssy  map[string]*big.Int

	VssEncy map[string]*paillier.Ciphertext
	MtAEncB map[string]*paillier.Ciphertext
	EncXi   *paillier.Ciphertext

	Beta    map[string]*big.Int
	Deltai  *big.Int
	Deltaix *big.Int
	Deltaiy *big.Int

	//presigning info
	Wix *big.Int
	Wiy *big.Int

	EncWi   *paillier.Ciphertext
	MtAEncW map[string]*paillier.Ciphertext

	Ki      *big.Int
	Kix     *big.Int
	Kiy     *big.Int
	Beta2   map[string]*big.Int
	Deltai2 *big.Int
	S       *big.Int
}
type MSecretPartiesInfoMap map[string]*SecretPartyInfo

//network 统一管理所有的公开信息。
//每一个party，应该有一个指针，指向自己的私有信息。

//公有信息包括
/*初始信息
N                     party人数
T                     阈值
Curve                 椭圆曲线的参数，
ID                    自己的唯一的ID标识符

PaillierKeyGen结束后的信息
Rtig                  本次签名的会话标识符
Rtigi                 后用作di
PaillierPublicKey     应该说是paillier的公钥
Aux                   pederson信息。

SM2TsKeyGen结束后的信息
X                     主公钥x^-1-1G
Xi                    小公钥xiG
Yi                    VSS分享后的小公钥sum(lambdai*Yi)=xG=A
A                     小公钥xG
PreSigning结束后的信息
R                     用于签名的随机数
Signing输入msg,待签名消息
r                     签名信息r
s                     签名信息s
*/

//私有信息
/*
PaillierKeyGen结束后的信息

PaillierSecertKey     paillier的私钥

SM2TsKeyGen结束后的信息
x                     小私钥sum(x)G=xG
y                     小私钥sum(lambdai*yi)G=xG
PreSigning结束后的信息(前面都是n个人，现在变成了t个人了)
w                     小私钥lambdai*yi
chi                   随机消息和私钥的sum(chi)=xk
Signing输入msg,待签名消息
清空w,chi
*/
