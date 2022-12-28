# zk-SNARK (Part2)

接上文，我们已经介绍了从NP问题到代数电路到R1CS再到QAP的转换过程概念，成功的将一个NP问题的验证问题转换成了一个多项式系数能否整除的验证问题。接下来，我们尝试把QAP应用于zkSNARK，这里我们用Groth16方案来进行分析。

## Groth16

在之前的文档中我们曾提到，Groth16计算快、生成的证明小，曾是公认的“最优”的zk-SNARK方案，也是Zcash Sapling协议的重要组成部分，也出现在Filecoin、Coda等其他项目当中。

按照惯例，我们先看一下论文的部分摘要：

> Non-interactive arguments enable a prover to convince a verifier that a statement is true. Recently there has been a lot of progress both in theory and practice on constructing highly efficient non-interactive arguments with small size and low verification complexity, so-called succinct non-interactive arguments (SNARGs) and succinct non-interactive arguments of knowledge (SNARKs). Many constructions of SNARGs rely on pairing-based cryptography. In these constructions a proof consists of a number of group elements and the verification consists of checking a number of pairing product equations. The question we address in this article is how efficient pairing-based SNARGs can be. Our first contribution is a pairing-based (preprocessing) SNARK for arithmetic circuit satisfiability, which is an NP-complete language. In our SNARK we work with asymmetric pairings for higher efficiency, a proof is only 3 group elements, and verification consists of checking a single pairing product equations using 3 pairings in total. Our SNARK is zero-knowledge and does not reveal anything about the witness the prover uses to make the proof.

非交互式的证明允许证明者让验证者确信某个陈述是正确的。近来我们看到很多理论和实践上的进展，关于构建高效率的、证明体积小的、验证简单的非交互式证明，它们被称为SNARGs和SNARKs。很多SNARGs方案都基于配对的加密方案（注：PBC，大部分是基于椭圆曲线的配对方案，这里可以简单理解SNARGs为类似ECC签名生成和验证的东西）构建。在这些构建中，一个证明通常包含多个群元素，而验证则通常检查多个配对的乘积等式。我们在这篇文章中关注的问题，是基于配对的SNARGs方案效率到底能有多高。我们的第一个贡献是提出一个基于配对的、有预设的SNARK方案，使用算数电路的可满足性进行验证，是一种NP完备的语言表述。在我们的SNARK方案中，我们使用非对称配对来提高效率，一个证明仅包含三个群元素，并且验证也使用三个独立配对的乘积等式。我们的SNARK是零知识的，在生成证明的时候不暴露证明者提供的证据的任何信息。

简要来说，Groth16的SNARK是有预设的、基于电路的、NP完备的、使用非对称加密的零知识证明方案。这里简单转载一下[其他人的Groth16论文解读](./Groth16%20%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0_mutourend%E7%9A%84%E5%8D%9A%E5%AE%A2.pdf)。

## NILP和Non-Interactive Argument

抛开前半段从R1CS到QAP的转换过程，略过NILP的定义，我们直接关注non-interactive zero-knowledge arguments of knowledge的四个算法和它们的输入输出：

0. 定义$\mathbb{R}$是一个关系生成器，输入安全参数，输出一个多项式时间内能够计算的二元映射关系$R$；
1. Setup算法，输入为relation $R$，输出为common reference string $\sigma$和相应的simulation trapdoor $\tau$；
2. Prove算法，输入为common reference string $\sigma$、$(\phi,w)\in R$，输出为argument $\pi$；
3. Verification算法，输入为common reference string $\sigma$、statement $\phi$、argument $\pi$，输出为0（reject） 或 1（accept）；
4. Simulator算法，输入为simulation trapdoor $\tau$、statement $\phi$，输出为argument $\pi$。

其中，Simulator算法是NILP中没有，但是在zk-SNARK同样重要的算法，它接收一个trapdoor和一个公开的statement，但是返回论据argument。

至此还没有用到我们生成的QAP，但是我们的QAP实际就是一个有效的relation $R$。

## 为QAP构架Non-Interactive Argument

我们的QAP接受公开的statement和用以证明的证据witness。根据QAP生成证明以及进行验证的内容在论文的3.1和3.2节，在论文解读的4.1和4.2节。

为QAP构架Non-Interactive Argument同样使用上面提到的四个算法，在下一部分中，我们将解读Groth16在Zcash中的实际应用。