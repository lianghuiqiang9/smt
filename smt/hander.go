package smt

import (
	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/round"
	"github.com/lianghuiqiang9/smt/smt/paillierkeygen"
	"github.com/lianghuiqiang9/smt/smt/presigning"
	"github.com/lianghuiqiang9/smt/smt/signing"
	"github.com/lianghuiqiang9/smt/smt/tskeygen"
	"math/big"
)

type SignInfo struct {
	Msg []byte
	R   *big.Int
	S   *big.Int
}

func Paillierkeygen(Net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	round.MRound(paillierkeygen.Round1, Net, SecretInfo)
	round.MRound(paillierkeygen.Output, Net, SecretInfo)
}

func Tskeygen(Net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	round.MRound(tskeygen.Round1, Net, SecretInfo)
	round.MRound(tskeygen.Round2, Net, SecretInfo)
	round.MRound(tskeygen.Round3, Net, SecretInfo)
	round.MRound(tskeygen.Round4, Net, SecretInfo)
	round.MRound(tskeygen.Round5, Net, SecretInfo)
	round.MRound(tskeygen.Output, Net, SecretInfo)
}
func Presigning(Net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	round.MRoundT(presigning.Round1, Net, SecretInfo)
	round.MRoundT(presigning.Round2, Net, SecretInfo)
	round.MRoundT(presigning.Output, Net, SecretInfo)
}
func Signing(Net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	round.MRoundT(signing.Round1, Net, SecretInfo)
	round.MRoundT(signing.Output, Net, SecretInfo)
}
