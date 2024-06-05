# 0 SMT
This is a threshold SM2 signature program.

# 1 Configure the Go environment

1. A simple command to install Go.

    sudo apt install golang

2. Or visit the official website to install the latest version.

    https://go.dev/dl/

# 2 Set up a Go proxy

    go env -w GO111MODULE=on
    go env -w  GOPROXY=https://goproxy.cn,direct

# 3 Compile and run

    go build
    go run main.go

# 4 Address of the paper

Non-interactive SM2 threshold signature scheme with identifiable abort

url : https://link.springer.com/article/10.1007/s11704-022-2288-x

url : https://journal.hep.com.cn/fcs/EN/10.1007/s11704-022-2288-x

Abstract

A threshold signature is a special digital signature in which the N-signer share the private key x and can construct a valid signature for any subset of the included t-signer, but less than $t$-signer cannot obtain any information. Considering the breakthrough achievements of threshold ECDSA signature and threshold Schnorr signature, the existing SM2 threshold signature is still limited to two parties or based on the honest majority setting, there is no more effective solution for the multiparty case. To make the SM2 signature have more flexible application scenarios, promote the application of the SM2 signature scheme in the blockchain system and secure cryptocurrency wallets. This paper designs a non-interactive SM2 threshold signature scheme based on partially homomorphic encryption and zero-knowledge proof. Only the last round requires the message input, so make our scheme non-interactive, and the pre-signing process takes 2 rounds of communication to complete after the key generation. We allow arbitrary threshold t<=n and design a key update strategy. It can achieve security with identifiable abort under the malicious majority, which means that if the signature process fails, we can find the failed party. Performance analysis shows that the computation and communication volume of the pre-signing process grows linearly with the parties, and it is only 1/3 of the Canetti's threshold ECDSA (CCS'20).

# 5 Note

1. The main time cost is in zk proof, improve the zk function will reduce a lot of time.

2. We only implement the abort when zk proof failed. Do not implement the identifiable abort now, it need to program the check process in VSS and MultiAdd(MTA). Maybe we do it in the future.

