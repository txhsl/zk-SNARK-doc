# Zcash Part1

Zcash旨在实现匿名安全的UTXO链上交易，通过使用zk-SNARK(Zero-Knowledge Succinct Non-Interactive Argument of Knowledge，无交互的、简要的、零知识的内容论证)隐藏交易中包含的地址、数额以及附加消息。交易双方可以自行验证交易的有效性，或是将有限的部分数据提供给可信的第三方进行审计。

> With Network Upgrade 5 (NU5) in May 2022, Zcash introduced the Orchard shielded payment protocol, which utilizes the Halo 2 zero-knowledge proving system. Halo is a new zk-SNARK that’s finally capable of solving two outstanding issues in Zcash: removing the trusted setup while hitting performance targets and supporting a scalable architecture for private digital payments.

在2022年5月的Network Upgrade 5 (NU5)升级后，Zcash推出了名为Orchard的隐匿支付协议。该协议基于Halo2零知识证明系统，提供了一种更加高效和可扩展的数字支付手段。

完备的零知识证明包含以下三种必要的特性：
1. 完整性 - 即如果证明描述的内容为真，则Prover可以让Verifier相信其为真；
2. 可靠性 - 即如果证明描述的内容为假，则Prover无法让Verifier相信其为真；
3. 隐匿性 - 即如果证明描述的内容为真，则Verifier只能从证明中得知该内容为真。

## 基础定义

> Zcash is an implementation of the Decentralized Anonymous Payment scheme Zerocash [BCGGMTV2014], with security fixes and improvements to performance and functionality. It bridges the existing transparent payment scheme used by Bitcoin [Nakamoto2008] with a shielded payment scheme secured by zero-knowledge succinct non-interactive arguments of knowledge (zk-SNARKs).

Zcash协议是Zerocash方案的一种改进实现，在Bitcoin定义的公开支付命名空间(Transparent Scheme)之外增加了由zk-SNARKs保护的“遮蔽”支付空间(Shielded Scheme)。通过两类Scheme之间的资产转移，Zcash实现了部分交易数据的隐私化。

Zcash的“遮蔽”支付空间都使用了一种类似UTXO的Note(定义一个转账数量和遮蔽的接受地址)概念完成转账，当一个地址向另一个地址转账时，输入的Note会在原地址下被销毁，但是新的Note会在目标地址下被铸造。命名空间的不同再加上遮蔽协议的不同，让UTXO和多种Note不能通用，Zcash的所有资产价值可以按照协议的命名空间进行划分，公开交易的资产属于Transparent Pool，Sprout协议遮蔽的资产就属于Sprout Pool，Sapling协议遮蔽的资产就属于Sapling Pool，Orchard协议遮蔽的资产就属于Orchard Pool。

![Zcash transaction](https://electriccoin.co/wp-content/uploads/2016/11/high-level-txn_v3.png)

一个Zcash的交易仍然包含输入(inputs)、输出(outputs)和运行脚本(scripts)，这让它们在Bitcoin协议中也可以使用。而被遮蔽的交易还会包含一段Description用以描述从input向output的转换计算过程。

“遮蔽”支付中的每一个Note都关联一个对应的Note Commitment和一个Nullifier，这和Bitcoin UTXO描述的output和input类似却稍有不同。Commitment是Note将来能够被消耗的承诺，而Nullifier是Note被消耗后作废的证明。

> In each shielded transfer, the nullifiers of the input notes are revealed (preventing them from being spent again)
and the commitments of the output notes are revealed (allowing them to be spent in future).

对于每一笔被遮蔽的Zcash交易，它总是揭露交易的inputs发生了作废，铸造outputs，并对outputs的将来可用性做出承诺。交易中的zk-SNARK证明和签名总是证明以下事件成立：

对于被遮蔽的input：

1. 当转账数量非零时，对应Note必然存在已暴露的Commitment；
2. Prover必然知晓使用该Note所需的Proof authorizing key；
3. Note的Commitment和销毁所用的Nullifier必然计算正确并且对应。

而对于被遮蔽的output：

1. 铸造Note所暴露的Commitment必然是正确的；
2. 销毁该Note所需的Nullifier和其他Note的Nullifier不会是相同的而导致冲突。

为保证交易不会被未经授权的第三方更改，Zcash在zk-SNARK以外还需要采取一些其他手段，比如检查交易使用的Nullifier没有在其他地方出现过。

## 账户&交易类型

![multiple transaction types](https://i.imgtg.com/2022/12/15/Ds6NM.png)

Zcash定义两种类型地址，分别是隐匿地址(z-addresses)和透明地址(t-addresses)，以下简称为Z地址和T地址。从Z地址到Z地址的交易被称为隐匿(private)交易，从T地址到T地址的交易被称为公开(public)交易，从Z地址到T地址的交易被称为暴露(deshielding)交易，从T地址到Z地址的交易被称为遮蔽(shielding)交易。

从Z地址向T地址转移资产会暴露UTXO的轨迹和账户的交易历史，而从T地址向Z地址转移资产则会反过来隐藏UTXO的轨迹和账户的交易历史。不过从统计数据上来说，透明交易仍是Zcash上的主流。

![shielded adoption](https://electriccoin.co/wp-content/uploads/2022/12/zcashtransactions.png)

一个被遮蔽的地址背后包含了一个非对称加密中的私钥。Key-private意味着交易包含的密文并不会暴露接收者的信息，除了私钥的持有者以外，也没有其他人知道密文所携带的实际内容。这个私钥在后文会被称为接收者密钥(receiving key)。

**Zcash保护隐私的关键就在于，当一个Note被消耗时，消耗者仅证明其对应的Commitment已经被暴露过了，但是不声明到底是哪一个Note被消耗了**。这意味处理Note的交易并不像UTXO的交易一样，被消耗的Note并不能找到其关联的那一笔铸造交易。从对手的角度来说，Note的可追溯性就显得极差。

## 交易地址和密钥

![Spending key](https://i.imgtg.com/2022/12/19/HpbDX.png)

Zcash中被遮蔽的支付地址都由一个spending key ($a_{sk}$)计算而来。上图分别描述了Sprout、Sapling和Orchard协议的密钥和遮蔽地址生成过程。

Sprout协议按序生成incoming viewing key ($ivk$)和shielded payment address ($addr_{pk}$)，其中$(ivk)=(a_{pk},sk_{enc})$，即左侧为spending key的公钥，被称为支付密钥(paying key)，右侧为另一个解密私钥，被称为接收密钥(receving key)；而$(addr_{pk})=(a_{pk},pk_{enc})$，即左侧仍为spending key的公钥，而右侧为解密私钥的加密公钥，被称为发送密钥(transmission key)。

Sapling协议生成的内容和顺序更为复杂，左侧按顺序先从spending key衍生出$ask$作为spend authorizing key，衍生出$nsk$作为nullifier private key，衍生出$ovk$作为outgoing viewing key，$(ask,nsk,ovk)$整体被称为expanded spending key。取$ask$的公钥$ak$构成$(ak,nsk)$被称为proof authorizing key，再取$nsk$的公钥$nk$构成$(ak,nk,ovk)$被称为full viewing key，其中$(ak,nk)$生成incoming viewing key，向上再引入随机数$d$和生成发送密钥$pk_d$构成shielded payment address。相比Sprout，Sapling协议允许同一个spending key生成多样化(Diversified)的shielded payment address。

Orchard协议则类似Sapling协议的一个简化，先从spending key衍生出$ask$作为spend authorizing key，取其公钥$ak$构成$(ak,nk,rivk)$作为full viewing key，从full viewing key再衍生出$(dk,ivk)$作为incoming viewing key，衍生出$ovk$作为outgoing viewing key，向上再生成$d$和发送密钥$pk_d$构成shielded payment address。

三种遮蔽协议的共通之处就是都定义了自己的spending key、viewing key (full viewing key或者incoming viewing key、outgoing viewing key)和transmission key。

> Note: It is conventional in cryptography to call the key used to encrypt a message in an asymmetric encryption scheme a “public key”. However, the public key used as the transmission key component of an address ($pk_{enc}$ or $pk_d$) need not be publically distributed; it has the same distribution as the shielded payment address itself.

## Notes

> A note (denoted $n$) can be a Sprout note or a Sapling note or an Orchard note. In each case it represents that a value $v$ is spendable by the recipient who holds the spending key corresponding to a given shielded payment address.

以上为Note的具体定义，即为发送给一个spending key持有者的，仅可由其使用的，数量$v$的原生资产。

在Sprout协议中，Note是一个可用$(a_{pk},v,ρ,rcm)$表示的元组：

![Sprout note](https://i.imgtg.com/2022/12/20/HRlub.png)

1. $a_{pk}$即为上文描述的接收者的paying key；
2. $v$即为Note发送的资产数量；
3. $ρ$为计算Note Nullifier所需的函数输入；
4. $rcm$为计算对应Note Commitment所需的陷门(Trapdoor)。

在Sapling协议中，Note是一个可用$(d,pk_d,v,rcm)$表示的元组：

![Sapling note](https://i.imgtg.com/2022/12/20/HRjzl.png)

1. $d$是接收者遮蔽地址中的Diversifier；
2. $pk_d$是接收者遮蔽地址的transmission key；
3. $v$,$rcm$的定义和上文相同。

在Orchard协议中，Note是一个可用$(d,pk_d,v,ρ,ψ,rcm)$表示的元组：

![Orchard note](https://i.imgtg.com/2022/12/20/HR2Pg.png)

1. $ψ$是计算Note Nullifier所需的一个额外随机值；
2. 其他符号的定义和上文相同。

当我们发送一个Note时，仅有一个Commitment会被暴露，并且该Commitment随即会被添加到链上的Commitment Tree上。这让交易的资产数量和接收者地址能够保持隐私，即便Commitment在zk-SNARK中进行验算，也只是证明它确实存在在区块链上。

Commitment的计算方法如下：

![Sprout commitment](https://i.imgtg.com/2022/12/20/HR69B.png)

![Sapling commitment](https://i.imgtg.com/2022/12/20/HRuvK.png)

![Orchard commitment](https://i.imgtg.com/2022/12/20/HRCOS.png)

具体的计算过程暂时省略，总的来说都是以$rcm$为工具、以Note的其他内容为输入计算Commitment。

而Nullifier，计算它们所需的条件来自Note和公开的接收者密钥：

1. Sprout协议中的Nullifier，使用Note中的$ρ$和接收者的spending key $a_{sk}$就可以计算获得；
2. Sapling协议中的Nullifier，使用Note中的$ρ$和接收者的nullifier生成密钥$nk$就可以计算获得；
3. Orchard协议中的Nullifier，使用Note中的$ρ,ψ$和接收者的nullifier生成密钥$nk$以及Commitment就可以计算获得。

在实际加密和传输的过程中，由spending key衍生的各种公开密钥(比如$a_{pk},pk_d$)虽然存在于Note的定义当中，但不需要被放入Note的明文中进行加密，因为它们不需要隐私保护。

## 区块链

> A path from the root toward the leaves of the tree consisting of a sequence of one or more valid blocks consistent with consensus rules, is called a valid block chain.

总体上来说，Zcash的区块链定义并不特殊，仍然是PoW的链式结构区块链，类似Bitcoin。

## 状态树理论抽象

和上文描述的类似，基于Note传递价值的Zcash交易和基于UTXO传递价值的Bitcoin交易没有特殊不同，不再赘述。

对于公开的交易而言，它们使用和Bitcoin UTXO一样的方式管理状态(unspent transaction output)。但是对于各遮蔽协议而言，它们需要额外的存储来管理Note的Commitment和Nullifier，对于Commitment而言这部分存储是树(Note Commitment Trees)，对于Nullifier而言这部分存储是集合(Nullifier Sets)，两者统称为一个树状态(treestate)。

在一个给定的区块链上，对于任意一个遮蔽协议，treestate都理应按照以下方式完成链接：

1. 第一个区块的treestate输入为空；
2. 每一个区块第一笔交易的treestate输入为上一个区块最后一笔交易的最终treestate；
3. 区块中每一笔交易的treestate输入为上一笔交易的最终treestate；
4. 每一个区块的最终treestate是区块中最后一笔交易的treestate输出。

以此方式连接的交易让treestate发生连续而不分叉的转换。

## Commitment树

Zcash的Commitment树是一棵只增的Merkle树，它不被用于防止双花，而是只记录产生过的Note Commitment，每层至多添加$2^{h}$个节点。

尽管Commitment树是只增的，但是每个协议能够使用的Merkle树深度都是有限的。Sprout协议只能使用到深度29，Sapling协议和Orchard协议只能使用到深度32。这意味着当Commitment的总数达到指定深度时，用户无法再使用对应的协议产生新的Commitment。

## Nullifier集合

Zcash的Nullifier集合是每个全节点验证者都需要维护的集合，逻辑上和treestate存在关联。当交易执行时，Nullifier会被暴露并加入到这个集合当中，并且产生一个新的treestate。在打包交易时，Nullifier必须被验证是唯一的，从而防止双花。

## Sprout

### JoinSplit Description

> A JoinSplit description is data included in a transaction that describes a JoinSplit transfer, i.e. a shielded value transfer. In Sprout, this kind of value transfer was the primary Zcash-specific operation performed by transactions.

JoinSplit description是Sprout交易携带的一部分数据，用于描述JoinSplit transfer的过程，比如遮蔽转账的过程。在Sprout中，每个JoinSplit description即为交易需要执行的Zcash特有的操作。每一笔交易都会携带JoinSplit description的一个序列。每一个JoinSplit description都指向一个Sprout treestate作为锚点。

交易中的每个JoinSplit description开始执行前，都接收来自treestate的Commitment和Nullifier作为输入，而执行结束后的treestate则会作为后续JoinSplit description执行所需的锚点，因此交易携带的JoinSplit descriptions描述的treestates也是一个序列，被称为间隙树状态序列(interstitial treestates)。

树状态序列必然是有间隙的，因为当一笔交易构造时，它并不知道自己最终会出现在哪个区块的哪个位置，不知道前面一笔交易会是谁，也不知道它的treestate输出是什么。它的treestate锚点只能和交易处在的最终位置独立，引用一个更早的锚点作为输入。

每个JoinSplit description的输入和输出必须是精确正确的，包括交易内不同的description不能消耗相同的Note导致双花，这不能通过共识保证，而是由对JoinSplit声明的内容进行验证才能保证。共识仅要求验证时：

1. 每笔交易的第一个JoinSplit description指向的treestate锚点必须是上一个区块的treestate输出；
2. 交易中的任意一个JoinSplit description指向的treestate锚点必须是之前某个区块的treestate输出或者是同一交易的之前某个JoinSplit description的treestate输出。

以上定义相对于上一节中的treestate链接方式，连接的紧密程度要求有所降低，但前者是理想状态下的排序结果，后者才具有可行性。

### 协议过程

![Sprout key](https://img-blog.csdnimg.cn/20190727232754960.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1R1cmtleUNvY2s=,size_16,color_FFFFFF,t_70)

在地址和密钥一节中我们已经了解Sprout的地址生成过程，进一步的，我们需要了解协议的秘密分享过程，也就是Note关键参数的传递过程：

![Sprout secret](https://img-blog.csdnimg.cn/20190727232848521.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1R1cmtleUNvY2s=,size_16,color_FFFFFF,t_70)

1. Prover从Verifier的接收地址中获得$a_{pk}$和$pk_{enc}$；
2. Prover生成一个随机的密钥对$(esk,epk)$，其中的$esk$经$pk_{enc}$加密获得一个可分享的秘密(shared secret)；
3. Prover以该secret为种子生成一个对称密钥$K_{enc}$，将Note的完整原文加密获得$Cenc$；
4. Prover将$Cenc$和$epk$放入JoinSplit description发送给Verifier；
5. Verifier使用自己$ivk$中的$sk_enc$再加上$epk$解密shared secret，就可以生成获得相同的$K_{enc}$；
6. Verifier解密出Note的完整原文，就可以通过SHA256函数和Prover校对Commitment的内容是否有效。

总的来说，Sprout的秘密交换过程就是以加密的方式将$K_{enc}$的生成元从Prover传递到Verifier，让双方能够完成相同的加密和解密，再使用不可逆的哈希函数完成默契校验，证明Commitment的有效性。整个过程比较的简单。

### 签名

但是，秘密的交换过程现在只能有Prover和Verifier能够知道其中的正确性，因此需要额外的JoinSplit description来向共识验证者证明Prover的销毁和铸造是有效的。其中的spending key签署有效性证明，最终表现为一个签名，被称为JoinSplit signature。

![JoinSplit signature](https://img-blog.csdnimg.cn/2019072723282985.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1R1cmtleUNvY2s=,size_16,color_FFFFFF,t_70)

隐私交易的签名同样需要保证发送者的地址隐私，因此Sprout中的Prover每次都单独生成一对随机的$(JoinSplitPrivateKey,JoinSplitPubKey)$用以生成交易签名。

为了防止其他人篡改交易的内容并使用其他密钥重新签名，从而篡改交易内容。Prover需要取$JoinSplitPubKey$分别和交易中所有的Nullifier生成签名的哈希$h_{sig}$，再加上自己的$a_{sk}$进行二次哈希放入交易，从而防止不知道$a_{sk}$的攻击者篡改交易内容。

### zk-SNARK

关于如何理解Sprout的zk-SNARK，我们需要回到零知识证明的三原则上。Validator需要从Sprout定义的遮蔽交易知道三件事：

1. Prover计算的Nullifier是可验证从消耗的Note的明文参数计算来的，并且在Nullifier集合中是未出现过的；
2. Prover计算的Commitment是可验证有效的，且铸造的资产数量和Nullifier是平衡的；
3. Prover计算的description是spending key签署的，且Prover持有spending key；
4. 但是，Note的明文参数和Prover的身份对于Validator是未知的。

以上的3.已经通过JoinSplit signature完成证明，而1.和2.则需要计算JoinSplit description才能验证。

前文提到，Sprout通过JoinSplit description声明表述value的平衡性，原因是Sprout是将整块的Nullifier和Commitment计算放入了电路计算中，让电路验证计算value的总和，这让电路显得很大，证明变得很长，计算的性能显得很差。

[zcash/libsnark](https://github.com/zcash/libsnark)对NP statement进行了一些举例：

> A computation can be expressed as an NP statement, in forms such as the following:
> - "The C program `foo`, when executed, returns exit code `0` if given the input `bar` and some additional input `qux`."
> - "The Boolean circuit `foo` is satisfiable by some input `qux`."
> - "The arithmetic circuit `foo` accepts the partial assignment `bar`, when extended into some full assignment `qux`."
> - "The set of constraints `foo` is satisfiable by the partial assignment `bar`, when extended into some full assignment `qux`."

开始计算前，这些NP statement需要被转变为相同含义的证明多项式。比如当我要证明自己知道方程$x^3+x+5=35$的解时，这一问题的证明多项式即为$x^3+x+5$，证明的隐秘输入为3时，输出即为35。

首先，libsnark接收一个计算公式转化为电路$C(x,out)$，$x$代表输入，$out$代表输入；

其次，生成函数$G$根据公式电路和随机种子生成证明密钥$pk$和验证密钥$vk$, $(pk,vk)=G(C,random())$；

然后，证明函数$P$接收一个隐秘输入$x$、计算结果$out$和证明密钥$pk$计算证明$proof=P(pk,out,x)$；

最后，验证函数$V$接收证明$proof$、计算结果$out$和验证密钥$vk$进行验证$V(vk,out,proof)=true$。

补个图，zk-SNARK先将计算公式转化为代数电路(Algebraic Circuit)，再转化为一阶约束系统(Rank-1 Constraint System, R1CS)，再转化为二次算数程序(Quadratic Arithmetic Program, QAP)，逐渐把一个复杂公式转换为电路门简单计算的大量组合。

![zk-SNARK](https://www.ipfsnews.cn/wp-content/uploads/2020/07/2020070207235842.png)

## Sapling

### Spend Transfers, Output Transfers, and their Descriptions

JoinSplit description仅用于Sprout协议，而Sapling协议使用Spend transfer描述被遮蔽的交易input、Output transfer描述被遮蔽的交易output，它们的Description分别独立，而不是放在一起。

对于Sapling协议而言，一个Spend transfer消耗掉一个旧的Note，而一个Output transfer铸造出一个新的Note。交易因此携带一个Spend description的序列和一个Output description的序列。

Sapling协议使用了同态加密来处理input和output标明的资产数量，这让交易双方以外的第三者可以直接对交易的输入输出平衡进行验证。

间隙树状态序列对于Sapling协议不是必需的，因为交易内不同的Spend description无法销毁相同的Note。这使得Sapling协议是高效的，因为协议不必保证交易中每个JoinSplit description的输入和输出必须是精确正确的，而是只需保证整个交易的输入输出是平衡的。共识仅验证：

1. 所有Spend transfer和Output transfer操作的资产数量总和和交易声明的$v$值是一致的；
2. 每个Spend description锚定的treestate必须是之前某个区块的最终treestate。

### 协议过程

![Sapling key](https://img-blog.csdnimg.cn/20190727232906942.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1R1cmtleUNvY2s=,size_16,color_FFFFFF,t_70)

在地址和密钥一节中我们已经了解Sapling的地址生成过程，进一步的，我们需要了解协议的秘密分享过程。首先是使用incoming viewing key的秘密分享：

![Sapling secret](https://img-blog.csdnimg.cn/20190727233053683.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1R1cmtleUNvY2s=,size_16,color_FFFFFF,t_70)

除了部分加密空间和哈希函数的区别外，和Sprout如出一辙。

其次是使用full viewing key的秘密分享，该过程额外引入了$ovk$这一密钥：

![Sapling secret](https://img-blog.csdnimg.cn/20190727233108712.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1R1cmtleUNvY2s=,size_16,color_FFFFFF,t_70)

1. Prover从Verifier的接收地址中获得$pk_{d}$；
2. Prover生成一个随机的密钥对$(esk,epk)$，其中的$esk$经$pk_{d}$加密获得一个可分享的秘密(shared secret)；
3. Prover以该secret为种子生成一个对称密钥$K_{enc}$，将Note的完整原文加密获得$Cenc$；
4. Prover从$ovk$和$epk$生成对称密钥$ock$，将$esk$和$pk_{d}$加密为$Cout$，连同$Cenc$发送给Verifier；
5. Verifier只$ovk$就可以联合$epk$生成$ock$，解密$Cout$和shared secret，就可以生成获得相同的$K_{enc}$；
6. Verifier解密出Note的完整原文，就可以通过Hash函数和Prover校对Commitment的内容是否有效。

总的来说，该过程免除了$ivk$的使用，但是整体思路和之前差别不大。

### 签名

和Sprout一样Sapling也需要对遮蔽交易进行签名，但是后者的签名能够证明交易的输入和输出是平衡的。

首先是Spend authorization signature，这个签名证明Prover有权销毁交易涉及的Note：

![Spend authorization signature](https://img-blog.csdnimg.cn/2019072723302136.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1R1cmtleUNvY2s=,size_16,color_FFFFFF,t_70)

总体过程和JoinSplit signature的生成过程类似。

其次是Binding signature，这个签名保证Prover销毁和铸造Note的value是平衡的：

![Binding signature](https://img-blog.csdnimg.cn/20190727233038401.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1R1cmtleUNvY2s=,size_16,color_FFFFFF,t_70)

如同之前提到的一样，这里用到了同态加密。Prover对每一个Spend description和Output description都取得一个随机数$rcv$并连同value $v$一起相加后加密为$cv$。

![bsk](https://i.imgtg.com/2022/12/22/HEGPP.png)

![bvk](https://i.imgtg.com/2022/12/22/HEQ9b.png)

对于Prover，他对所有的$rcv$求和再求差，生成一个余额私钥$bsk$。对于Validator，他对$cv$求和再求差，再减去透明交易的value，生成公钥$bvk$。两个密钥分别用于交易的签名和验证。

### zk-SNARK

Sapling的zk-SNARK的目的和Sprout和相同的，也是向Validator证明三件事：

1. Prover计算的Nullifier是可验证从消耗的Note的明文参数计算来的，并且在Nullifier集合中是未出现过的；
2. Prover计算的Commitment是可验证有效的，且铸造的资产数量和Nullifier是平衡的；
3. Prover计算的description是spending key签署的，且Prover持有spending key；
4. 但是不暴露Note的明文参数和Prover的身份。

相比于Sprout，Sapling中的签名不仅完成了3.的证明，也完成了2.中的value平衡证明。再加上Sapling将整块的JoinSplit description拆分成了多个独立的Spend description和Output description，这让证明电路变得简单，并行性也得到了提升。

Sprout的定义曾大量引用了BCTV14a方案完成zk-SNARK，而Sapling更多的则是使用Groth16方案。虽然libsnark后续也增加了这一方案的支持，但是这回Zcash使用了自己的Rust库[zcash/librustzcash](https://github.com/zcash/librustzcash)，该算法库也被称为bellman算法库。相比于BCTV14a，Groth16的安全性证明依赖Generic Group Model，以更强的安全假设换得了更好的性能和更短的证明。

## Orchard

### Action Transfers and their Descriptions

Orchard协议介绍另一种不同的Action transfer，和一组Spend transfer和Output transfer不同，一个Action transfer可选地进行一次spend，以及可选地进行一次output。同样的，Orchard使用Action description描述Action transfer。NU5后的交易都能够携带一组Action description。

当Action transfer消耗一个旧的Note并铸造一个新的时，它的description提供一个包含前后Note资产数量差值的Commitment。因此和Sapling协议类似，同态加密同样允许交易双方以外的第三者直接验证交易的输入输出平衡情况。

一个Action description可以被视作是一个Spend descriptio和一个Output description的一个整合，但是只提供一个value的Commitment。每个Action description相互独立，这让它们不再需要锚定任何的treestate，而是直接使用交易提供的treestate。

间隙树状态序列对于Orchard协议也不是必需的，因为Action description无法销毁交易内其他description铸造的Note。共识仅验证：

1. 所有Action description操作的资产数量总和和交易声明的$v$值是一致的；
2. 每个交易锚定的treestate必须是之前某个区块的最终treestate。

### 协议过程

在地址和密钥一节中我们已经了解Orchard的地址生成过程，进一步的，我们需要了解协议的秘密分享过程。

我们先回到密钥与地址的定义上来，直接比较Orchard和Sapling的[改进之处](https://zcash.github.io/orchard/design/keys.html)，其中最主要的就是用Pallas曲线代替Jubjub曲线：

![Spending key](https://i.imgtg.com/2022/12/19/HpbDX.png)

第一，被称为Nullifier private key的$nsk$被移除，计算变得更快。

> Its purpose in Sapling was as defense-in-depth, in case RedDSA was found to have weaknesses; an adversary who could recover $ask$ would not be able to spend funds. In practice it has not been feasible to manage $nsk$ much more securely than a full viewing key, as the computational power required to generate Sapling proofs has made it necessary to perform this step on the same device that is creating the overall transaction (rather than on a more constrained device like a hardware wallet). We are also more confident in RedDSA now.

Sapling在Nullifier中应用非对称加密的原因在于对RedDSA的安全不自信，但是对$nsk$管理相比于管理full viewing key反而是更不安全的，因为Sapling证明必须在构建交易的设备上计算，而不能在更为安全的其他钱包设备上生成。再加上Zcash现在对RedDSA的安全更加自信，新的$nk$不再来自于曲线。

第二，$ovk$现在从$fvk$派生，而不是从$sk$。这能够避免两个$fvk$会具有相同的$ivk$但$ovk$不同的问题。

第三，所有的$d$取值都能够生成有效的payment address，这归功于向Pallas的群哈希映射(group hashing into Pallas)是必然成功的，消除了地址生成过程中一个关键的复杂度。

第四，Orchard使用的Pallas是一条素数阶曲线，直接简化了密钥协议的计算过程，电路的计算也变得简单。文档还提到Orchard期望在将来使用Pallas-Vesta curve cycle，其中Vesta曲线已被用于Halo2证明的计算。

> Other than the above, Orchard retains the same design rationale for its keys and addresses as Sapling. For example, diversifiers remain at 11 bytes, so that a raw Orchard address is the same length as a raw Sapling address.

除上述变化以外，Orchard和Sapling的密钥和地址设计思路是几乎相同的，甚至不同类型的地址能够绑定在一起。

接下来再看Action description的对比。

> In Sprout, we had a single proof that represented two spent notes and two new notes. This was necessary in order to facilitate spending multiple notes in a single transaction (to balance value, an output of one JoinSplit could be spent in the next one), but also provided a minimal level of arity-hiding: single-JoinSplit transactions all looked like 2-in 2-out transactions, and in multi-JoinSplit transactions each JoinSplit looked like a 1-in 1-out.

> In Sapling, we switched to using value commitments to balance the transaction, removing the min-2 arity requirement. We opted for one proof per spent note and one (much simpler) proof per output note, which greatly improved the performance of generating outputs, but removed any arity-hiding from the proofs (instead having the transaction builder pad transactions to 1-in, 2-out).

Sprout提供了两进两出的Note销毁和铸造过程，但是Sapling通过交易中的同态价值承诺来保证资产平衡。这让每个输入的证明和输出的证明都变得简单，但是没有办法隐藏交易销毁和铸造Note的真实数量。

> For Orchard, we take a combined approach: we define an Orchard transaction as containing a bundle of actions, where each action is both a spend and an output. This provides the same inherent arity-hiding as multi-JoinSplit Sprout, but using Sapling value commitments to balance the transaction without doubling its size.

在Orchard中，交易表达的内容既是一组动作，又使用同态价值承诺来保证资产平衡，这同时做到了Note数量的遮蔽和资产平衡的简单证明，而交易的规模仍保持在较小的水平。

所以我们可以直接从Sprout和Sapling中找到Orchard的组成部分：

1. Orchard secret sharing的过程和Sapling相同，但是计算更快；
2. Orchard transaction的组成结构和Sprout类似，仅包含一块Action field而不是一块Spend和一块Output；
3. Orchard transaction的资产平衡验证方式和Sapling相同，但是直接对每个Action description的value直接求和，而不是先求和再求差；
4. Orchard transaction的签名生成过程也因此和Sapling类似，只不过签名机制从RedJubjub转变成了RedPallas(两者分别为Jubjub曲线和Pallas曲线下的RedDSA签名)。

### zk-SNARK

重复的内容就不再说明，我们直接来看Orchard使用的Halo2证明系统。

Groth16曾是公认的“最优”的zk-SNARK方案，它计算快、生成的证明小，总是被用作其他方案在实验时的对照对象。但是该方案并非是通用的，对不同的电路，参数的可信初始化过程是不同的。

Halo相比于Groth16不需要开头的可信初始化，并且支持递归的证明合成(Nested Amortization)，也就是通过椭圆曲线的循环重复地将多个证明折叠在一起。唯一可惜的是Halo的验证时间相对于电路大小是线性的，导致算法不满足简洁性(succinct)。

经过改进的Halo2不再用R1CS来表述电路，而是使用Plonk Arithmetization。而针对验证的简洁性问题，Halo2提出在验证电路中也进行Nested Amortization。我们说Halo需要验证参数b和参数G，参数b的计算复杂度是对数的，而参数G的计算是线性的，但证明电路默认了参数G的正确性，将验证多个proof的计算缩减到一个折叠后的proof上，让复杂度从O(n)降低到O(log(n))。

## 协议比较

| | Sprout | Sapling | Orchard |
| ---: | ---- | ---- | ---- |
|证明时间|37s|7s|暂无|
|内存占用|>3GB|40MB|暂无|

## 未解读的资料

1. [Groth16](https://eprint.iacr.org/2016/260);
2. [Halo](https://eprint.iacr.org/2019/1021);
3. [Halo2](https://trapdoor-tech.github.io/halo2-book-chinese/index.html);