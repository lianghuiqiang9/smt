package smt

import (
	"math/big"

	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/round"
	"github.com/lianghuiqiang9/smt/smt/paillierkeygen"
	"github.com/lianghuiqiang9/smt/smt/presigning"
	"github.com/lianghuiqiang9/smt/smt/signing"
	"github.com/lianghuiqiang9/smt/smt/tskeygen"
)

type SignInfo struct {
	Msg []byte
	R   *big.Int
	S   *big.Int
}

func Paillierkeygen(net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	round.MRound(paillierkeygen.Round1, net, SecretInfo)
	round.MRound(paillierkeygen.Output, net, SecretInfo)
}

func Tskeygen(net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	round.MRound(tskeygen.Round1, net, SecretInfo)
	round.MRound(tskeygen.Round2, net, SecretInfo)
	round.MRound(tskeygen.Round3, net, SecretInfo)
	round.MRound(tskeygen.Round4, net, SecretInfo)
	round.MRound(tskeygen.Round5, net, SecretInfo)
	round.MRound(tskeygen.Output, net, SecretInfo)
}
func Presigning(net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	round.MRoundT(presigning.Round1, net, SecretInfo)
	round.MRoundT(presigning.Round2, net, SecretInfo)
	round.MRoundT(presigning.Output, net, SecretInfo)
}
func Signing(net *network.Network, SecretInfo network.MSecretPartiesInfoMap) {
	round.MRoundT(signing.Round1, net, SecretInfo)
	round.MRoundT(signing.Output, net, SecretInfo)
}
