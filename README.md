# smt
This is a threshold SM2 signature program.
It still need to be tested before they can be used, only for learning and communication.

Abstract

A threshold signature is a special digital signature in which the N-signer share the private key x and can construct a valid signature for any subset of the included t-signer, but less than $t$-signer cannot obtain any information. Considering the breakthrough achievements of threshold ECDSA signature and threshold Schnorr signature, the existing SM2 threshold signature is still limited to two parties or based on the honest majority setting, there is no more effective solution for the multiparty case. To make the SM2 signature have more flexible application scenarios, promote the application of the SM2 signature scheme in the blockchain system and secure cryptocurrency wallets. This paper designs a non-interactive SM2 threshold signature scheme based on partially homomorphic encryption and zero-knowledge proof. Only the last round requires the message input, so make our scheme non-interactive, and the pre-signing process takes 2 rounds of communication to complete after the key generation. We allow arbitrary threshold t<=n and design a key update strategy. It can achieve security with identifiable abort under the malicious majority, which means that if the signature process fails, we can find the failed party. Performance analysis shows that the computation and communication volume of the pre-signing process grows linearly with the parties, and it is only 1/3 of the Canetti's threshold ECDSA (CCS'20).


2022/10/30
Its time to renew this program, the main priniple is not, the point is the paillier encryption.
and we should build the object, not one and one function.
and the big problem is safenet to bigint, everything is changed. we can do it. come on. one and one function to modify.

2022/4/13

Now, we have optimized the paillier encryption, and the speed has increased by 7 times, but it is still far from enough. The main changes are as follows
1. My level is limited, and I haven't written great code. Regarding the paillier encryption module, I refer to github.com/roasbeef/go-go-gadget-paillier, and copied part of it (because the function is written differently, it cannot be called directly ). In the original paillier encryption, (N+1)^mmod N^2 is changed to Nm+1modN^2. In addition, the decryption uses the Chinese remainder theorem (CRT), the ExpI of point multiplication is replaced.
2. Please refer to https://journal.hep.com.cn/fcs/EN/10.1007/s11704-022-2288-x DOI: 10.1007/s11704-022-2288-x for theoretical running time

现在，我们对paillier加密做了优化，速度提高了7倍，但是仍然远远不够. 主要改动如下
1. 本人水平有限，没有写出很棒的代码，关于paillier加密模块，我参考了github.com/roasbeef/go-go-gadget-paillier，并复制了其中一部分（因为函数写法不同，无法直接调用）。对原有的paillier 加密中 （N+1）^mmod N^2变为Nm+1modN^2,另外，解密用了中国剩余定理(CRT)，对点乘的ExpI进行了替换。
2. 理论运行时间请看https://journal.hep.com.cn/fcs/EN/10.1007/s11704-022-2288-x

