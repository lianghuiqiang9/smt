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
