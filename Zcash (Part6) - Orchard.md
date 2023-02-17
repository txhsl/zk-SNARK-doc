# Zcash (Part6) - Orchard

和Sapling协议不同，Orchard做出的改动并非电路逻辑上的改良，而是对ZK加密方案的替换。为此，我们需要知道Orchard提出的技术背景，

1. Sprout和Sapling都无法与现有的性能扩展技术兼容。Zcash期望使用Recursive zero-knowledge proofs (可循环折叠的证明)，但是从Sprout中使用哈希函数而非椭圆曲线计算密钥，到Sapling中开始使用的Jubjub曲线，都还和该技术的理论要求存在距离；
2. Sprout和Sapling使用的Groth16证明方案，需要一个可信的初始化，也就是从MPC计算公共SRS。只要MPC参与方中有一方诚实就可以完成参数生成，但是客观上这一过程是不可逆的。基于MPC方案的初始化本身来说就是一个风险点。Sprout在BCTV14时期就因为证明方案的一个漏洞，使得Sprout证明能够被伪造，最后导致了一次升级，要求了一次全面的新MPC。

## Orchard证明

和Sapling稍有不同，Orchard现阶段是zcash/zcash的一个外部调用，我们可以在[zcash/orchard](https://github.com/zcash/orchard)找到它。因此Orchard的调用路线和之前两个协议的“zcash->librustzcash->bellman”调用路线会有明显不同。

### 电路理论

受制于巨大的篇幅和代码量，下面的内容并不能直观解释Orchard电路的不同之处，这里尝试先用一些简单的理论解释其中的原理。

#### 椭圆曲线

在上一部分，我们已经知道Sapling使用了BLS12-381上构建的一条扭曲爱德华椭圆曲线（Twisted Edwards Curve）实现ECC，而Orchard使用了以下两条Pallas和Vesta曲线，

> Pallas: $y^2=x^3+5$ over $GF(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001)$
Vesta: $y^2=x^3+5$ over $GF(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001)$

很明显，两条曲线是同一个方程，所以Zcash也称之为[Pasta curves](https://github.com/zcash/pasta_curves)。这条曲线的特殊性在于任意曲线上的阶(order)是另一条曲线上的基域(base field)，也就是可以对结果进行二次甚至循环的计算。详细关于为什么使用两条曲线以及计算方式，可以阅读[这篇](https://www.michaelstraka.com/posts/recursivesnarks/)。

我们知道Sapling中曲线的变换是为了简化哈希的计算，而Pasta curves让证明的折叠变得简单，具体可以参照[这篇博客](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/)。不仅原本Jubjub的性质和Montgomery算法可行性得到保留，曲线上多项式计算的性能也得到大幅提升。

#### Sinsemilla哈希

> SinsemillaHash is an algebraic hash function with collision resistance (for fixed input length) derived from assumed hardness of the Discrete Logarithm Problem. The motivation for introducing a new discrete-logarithm-based hash function (rather than using PedersenHash) is to make efficient use of the lookups available in recent proof systems including Halo 2.

Sinsemilla哈希是一种对于固定长度输入具有抗碰撞性的哈希函数，使用其的目的在于让Halo 2中的lookup操作变得更有效率。

其结果是，Sinsemilla哈希代替Pedersen哈希，被用于note commitment和merkel root的计算，两者并不要求同态的性质。

#### Poseidon哈希

Poseidon最大的特点和优势在于所有运算均在有限域内完成，即均为模运算，针对零知识证明协议做了特定优化，能够够显著降低证明生成的计算复杂度。Poseidon哈希代替BLAKE2s，被用于nullifier的计算。

#### 证明递归

证明的递归(rollup)指的是将上一个证明的结果作为下一个证明的输入，由此实现证明的串联，用最后一个证明的结果前向覆盖之前所有的输入。证明的“串联”并不意味着其生成过程的并行不可行，我们已经了解曲线循环的特性，也知道之前协议证明结果的形式表达，用一句话来说，我们可以先计算出每个单独的证明，然后用循环计算的方法把它们串联起来，一次曲线上的计算就可以串联两个结果。

### 证明电路

Orchard将证明部分代码划分为Circuit、Chip和Gadget三个大类，其中Chip是新的概念引入，相当于我们理解的子电路，比如JoinSplit的`InputNote`和`OutputNote`。

#### Circuit

我们先从熟悉的电路开始。Orchard基于Halo2重新实现了Action电路，我们可以在[zcash/orchard/src/circuit.rs](https://github.com/zcash/orchard/blob/5fbbded49e3162a31fd3bb0de3c344f3cc4dfa60/src/circuit.rs)找到其中的集成电路，

```rust
pub struct Circuit {
    pub(crate) path: Value<[MerkleHashOrchard; MERKLE_DEPTH_ORCHARD]>,
    pub(crate) pos: Value<u32>,
    pub(crate) g_d_old: Value<NonIdentityPallasPoint>,
    pub(crate) pk_d_old: Value<DiversifiedTransmissionKey>,
    pub(crate) v_old: Value<NoteValue>,
    pub(crate) rho_old: Value<Nullifier>,
    pub(crate) psi_old: Value<pallas::Base>,
    pub(crate) rcm_old: Value<NoteCommitTrapdoor>,
    pub(crate) cm_old: Value<NoteCommitment>,
    pub(crate) alpha: Value<pallas::Scalar>,
    pub(crate) ak: Value<SpendValidatingKey>,
    pub(crate) nk: Value<NullifierDerivingKey>,
    pub(crate) rivk: Value<CommitIvkRandomness>,
    pub(crate) g_d_new: Value<NonIdentityPallasPoint>,
    pub(crate) pk_d_new: Value<DiversifiedTransmissionKey>,
    pub(crate) v_new: Value<NoteValue>,
    pub(crate) psi_new: Value<pallas::Base>,
    pub(crate) rcm_new: Value<NoteCommitTrapdoor>,
    pub(crate) rcv: Value<ValueCommitTrapdoor>,
}

impl Circuit {
    /// This constructor is public to enable creation of custom builders.
    /// If you are not creating a custom builder, use [`Builder`] to compose
    /// and authorize a transaction.
    ///
    /// Constructs a `Circuit` from the following components:
    /// - `spend`: [`SpendInfo`] of the note spent in scope of the action
    /// - `output_note`: a note created in scope of the action
    /// - `alpha`: a scalar used for randomization of the action spend validating key
    /// - `rcv`: trapdoor for the action value commitment
    ///
    /// Returns `None` if the `rho` of the `output_note` is not equal
    /// to the nullifier of the spent note.
    ///
    /// [`SpendInfo`]: crate::builder::SpendInfo
    /// [`Builder`]: crate::builder::Builder
    pub fn from_action_context(
        spend: SpendInfo,
        output_note: Note,
        alpha: pallas::Scalar,
        rcv: ValueCommitTrapdoor,
    ) -> Option<Circuit> {
        (spend.note.nullifier(&spend.fvk) == output_note.rho())
            .then(|| Self::from_action_context_unchecked(spend, output_note, alpha, rcv))
    }

    /// 从context获取action包含的信息，传入电路
    pub(crate) fn from_action_context_unchecked(
        spend: SpendInfo, // Spend
        output_note: Note, // Output
        alpha: pallas::Scalar,
        rcv: ValueCommitTrapdoor,
    ) -> Circuit {
        // 销毁note的接收地址，熟悉的rho和随机种子rseed
        let sender_address = spend.note.recipient();
        let rho_old = spend.note.rho();
        let psi_old = spend.note.rseed().psi(&rho_old);
        let rcm_old = spend.note.rseed().rcm(&rho_old);
        // 铸造note的rho和rseed
        let rho_new = output_note.rho();
        let psi_new = output_note.rseed().psi(&rho_new);
        let rcm_new = output_note.rseed().rcm(&rho_new);

        Circuit {
            // merkle_path
            path: Value::known(spend.merkle_path.auth_path()),
            pos: Value::known(spend.merkle_path.position()),
            // sender_address
            g_d_old: Value::known(sender_address.g_d()),
            pk_d_old: Value::known(*sender_address.pk_d()),
            // spend_note
            v_old: Value::known(spend.note.value()),
            rho_old: Value::known(rho_old),
            psi_old: Value::known(psi_old),
            rcm_old: Value::known(rcm_old),
            cm_old: Value::known(spend.note.commitment()),
            // action的随机种子alpha
            alpha: Value::known(alpha),
            // spending_key的衍生密钥full_viewing_key
            ak: Value::known(spend.fvk.clone().into()),
            nk: Value::known(*spend.fvk.nk()),
            rivk: Value::known(spend.fvk.rivk(spend.scope)),
            // output_note
            g_d_new: Value::known(output_note.recipient().g_d()),
            pk_d_new: Value::known(*output_note.recipient().pk_d()),
            v_new: Value::known(output_note.value()),
            psi_new: Value::known(psi_new),
            rcm_new: Value::known(rcm_new),
            // value_commitment需要的随机量
            rcv: Value::known(rcv),
        }
    }
}
```

这里定义的`Circuit`不再是我们之前理解的广义电路，而是包含多个芯片的Orchard专用集成电路。除了些许的不同，上述电路要求的参数都和Sapling电路使用的参数类似，而电路又重新合并为整块，这一点和Sprout类似。

让我们感到陌生的应当是电路约束的转换过程，Orchard使用下面的方法设置和加载电路，

```rust
impl plonk::Circuit<pallas::Base> for Circuit {
    type Config = Config;
    type FloorPlanner = floor_planner::V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    /// 集成电路的设置方法，创建一些基础约束
    fn configure(meta: &mut plonk::ConstraintSystem<pallas::Base>) -> Self::Config {
        // Advice columns used in the Orchard circuit.
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        /// 对于Orchard action的约束
        /// value平衡的约束
        // Constrain v_old - v_new = magnitude * sign    (https://p.z.cash/ZKS:action-cv-net-integrity?partial).
        /// merkle root相同的约束
        // Either v_old = 0, or calculated root = anchor (https://p.z.cash/ZKS:action-merkle-path-validity?partial).
        /// action是否配置spend输入和实际情况相同的约束
        // Constrain v_old = 0 or enable_spends = 1      (https://p.z.cash/ZKS:action-enable-spend).
        /// action是否配置output输出和实际情况相同的约束
        // Constrain v_new = 0 or enable_outputs = 1     (https://p.z.cash/ZKS:action-enable-output).
        let q_orchard = meta.selector();
        meta.create_gate("Orchard circuit checks", |meta| {
            let q_orchard = meta.query_selector(q_orchard);
            let v_old = meta.query_advice(advices[0], Rotation::cur());
            let v_new = meta.query_advice(advices[1], Rotation::cur());
            let magnitude = meta.query_advice(advices[2], Rotation::cur());
            let sign = meta.query_advice(advices[3], Rotation::cur());

            let root = meta.query_advice(advices[4], Rotation::cur());
            let anchor = meta.query_advice(advices[5], Rotation::cur());

            let enable_spends = meta.query_advice(advices[6], Rotation::cur());
            let enable_outputs = meta.query_advice(advices[7], Rotation::cur());

            let one = Expression::Constant(pallas::Base::one());

            Constraints::with_selector(
                q_orchard,
                [
                    (
                        "v_old - v_new = magnitude * sign",
                        v_old.clone() - v_new.clone() - magnitude * sign,
                    ),
                    (
                        "Either v_old = 0, or root = anchor",
                        v_old.clone() * (root - anchor),
                    ),
                    (
                        "v_old = 0 or enable_spends = 1",
                        v_old * (one.clone() - enable_spends),
                    ),
                    (
                        "v_new = 0 or enable_outputs = 1",
                        v_new * (one - enable_outputs),
                    ),
                ],
            )
        });

        /// 调用加法芯片的设置
        // Addition of two field elements.
        let add_config = AddChip::configure(meta, advices[7], advices[8], advices[6]);

        /// 准备Sinsemilla哈希芯片的设置做准备
        // Fixed columns for the Sinsemilla generator lookup table
        let table_idx = meta.lookup_table_column();
        let lookup = (
            table_idx,
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

        // Instance column used for public inputs
        let primary = meta.instance_column();
        meta.enable_equality(primary);

        // Permutation over all advice columns.
        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        /// 为Poseidon哈希芯片和ECC芯片的设置做准备
        // Poseidon requires four advice columns, while ECC incomplete addition requires
        // six, so we could choose to configure them in parallel. However, we only use a
        // single Poseidon invocation, and we have the rows to accommodate it serially.
        // Instead, we reduce the proof size by sharing fixed columns between the ECC and
        // Poseidon chips.
        let lagrange_coeffs = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let rc_a = lagrange_coeffs[2..5].try_into().unwrap();
        let rc_b = lagrange_coeffs[5..8].try_into().unwrap();

        /// 预留全局约束的空间
        // Also use the first Lagrange coefficient column for loading global constants.
        // It's free real estate :)
        meta.enable_constant(lagrange_coeffs[0]);

        /// 调用范围验证芯片的设置
        // We have a lot of free space in the right-most advice columns; use one of them
        // for all of our range checks.
        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

        /// 设置ECC芯片
        // Configuration for curve point operations.
        // This uses 10 advice columns and spans the whole circuit.
        let ecc_config =
            EccChip::<OrchardFixedBases>::configure(meta, advices, lagrange_coeffs, range_check);

        /// 设置Poseidon哈希芯片
        // Configuration for the Poseidon hash.
        let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
            meta,
            // We place the state columns after the partial_sbox column so that the
            // pad-and-add region can be laid out more efficiently.
            advices[6..9].try_into().unwrap(),
            advices[5],
            rc_a,
            rc_b,
        );

        /// 设置Sinsemilla哈希芯片，和一个使用该哈希的Merkle计算芯片
        // Configuration for a Sinsemilla hash instantiation and a
        // Merkle hash instantiation using this Sinsemilla instance.
        // Since the Sinsemilla config uses only 5 advice columns,
        // we can fit two instances side-by-side.
        let (sinsemilla_config_1, merkle_config_1) = {
            let sinsemilla_config_1 = SinsemillaChip::configure(
                meta,
                advices[..5].try_into().unwrap(),
                advices[6],
                lagrange_coeffs[0],
                lookup,
                range_check,
            );
            let merkle_config_1 = MerkleChip::configure(meta, sinsemilla_config_1.clone());

            (sinsemilla_config_1, merkle_config_1)
        };

        /// 再设置一份
        // Configuration for a Sinsemilla hash instantiation and a
        // Merkle hash instantiation using this Sinsemilla instance.
        // Since the Sinsemilla config uses only 5 advice columns,
        // we can fit two instances side-by-side.
        let (sinsemilla_config_2, merkle_config_2) = {
            let sinsemilla_config_2 = SinsemillaChip::configure(
                meta,
                advices[5..].try_into().unwrap(),
                advices[7],
                lagrange_coeffs[1],
                lookup,
                range_check,
            );
            let merkle_config_2 = MerkleChip::configure(meta, sinsemilla_config_2.clone());

            (sinsemilla_config_2, merkle_config_2)
        };

        /// 调用设置ivk芯片
        // Configuration to handle decomposition and canonicity checking
        // for CommitIvk.
        let commit_ivk_config = CommitIvkChip::configure(meta, advices);

        /// 调用设置旧note的处理电路
        // Configuration to handle decomposition and canonicity checking
        // for NoteCommit_old.
        let old_note_commit_config =
            NoteCommitChip::configure(meta, advices, sinsemilla_config_1.clone());

        /// 调用设置新note的处理电路
        // Configuration to handle decomposition and canonicity checking
        // for NoteCommit_new.
        let new_note_commit_config =
            NoteCommitChip::configure(meta, advices, sinsemilla_config_2.clone());

        /// 返回所有设置
        Config {
            primary,
            q_orchard,
            advices,
            add_config,
            ecc_config,
            poseidon_config,
            merkle_config_1,
            merkle_config_2,
            sinsemilla_config_1,
            sinsemilla_config_2,
            commit_ivk_config,
            old_note_commit_config,
            new_note_commit_config,
        }
    }

    /// 使用以上设置的电路加载方法
    #[allow(non_snake_case)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), plonk::Error> {
        /// 使用config_1加载一个Sinsemilla芯片
        // Load the Sinsemilla generator lookup table used by the whole circuit.
        SinsemillaChip::load(config.sinsemilla_config_1.clone(), &mut layouter)?;

        /// 获得ECC芯片的模板
        // Construct the ECC chip.
        let ecc_chip = config.ecc_chip();

        /// 使用以上两个电路见证以下输入
        // Witness private inputs that are used across multiple checks.
        let (psi_old, rho_old, cm_old, g_d_old, ak_P, nk, v_old, v_new) = {
            // Witness psi_old
            let psi_old = assign_free_advice(
                layouter.namespace(|| "witness psi_old"),
                config.advices[0],
                self.psi_old,
            )?;

            // Witness rho_old
            let rho_old = assign_free_advice(
                layouter.namespace(|| "witness rho_old"),
                config.advices[0],
                self.rho_old.map(|rho| rho.0),
            )?;

            // Witness cm_old
            let cm_old = Point::new(
                ecc_chip.clone(),
                layouter.namespace(|| "cm_old"),
                self.cm_old.as_ref().map(|cm| cm.inner().to_affine()),
            )?;

            // Witness g_d_old
            let g_d_old = NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| "gd_old"),
                self.g_d_old.as_ref().map(|gd| gd.to_affine()),
            )?;

            // Witness ak_P.
            let ak_P: Value<pallas::Point> = self.ak.as_ref().map(|ak| ak.into());
            let ak_P = NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| "witness ak_P"),
                ak_P.map(|ak_P| ak_P.to_affine()),
            )?;

            // Witness nk.
            let nk = assign_free_advice(
                layouter.namespace(|| "witness nk"),
                config.advices[0],
                self.nk.map(|nk| nk.inner()),
            )?;

            // Witness v_old.
            let v_old = assign_free_advice(
                layouter.namespace(|| "witness v_old"),
                config.advices[0],
                self.v_old,
            )?;

            // Witness v_new.
            let v_new = assign_free_advice(
                layouter.namespace(|| "witness v_new"),
                config.advices[0],
                self.v_new,
            )?;

            (psi_old, rho_old, cm_old, g_d_old, ak_P, nk, v_old, v_new)
        };

        /// 验证计算旧note的Merkle root
        // Merkle path validity check (https://p.z.cash/ZKS:action-merkle-path-validity?partial).
        let root = {
            let path = self
                .path
                .map(|typed_path| typed_path.map(|node| node.inner()));
            let merkle_inputs = MerklePath::construct(
                [config.merkle_chip_1(), config.merkle_chip_2()],
                OrchardHashDomains::MerkleCrh,
                self.pos,
                path,
            );
            let leaf = cm_old.extract_p().inner().clone();
            merkle_inputs.calculate_root(layouter.namespace(|| "Merkle path"), leaf)?
        };

        /// 处理value commitment
        // Value commitment integrity (https://p.z.cash/ZKS:action-cv-net-integrity?partial).
        let v_net_magnitude_sign = {
            /// 获得v_old - v_new这一结果的符号和数量
            // Witness the magnitude and sign of v_net = v_old - v_new
            let v_net_magnitude_sign = {
                let v_net = self.v_old - self.v_new;
                let magnitude_sign = v_net.map(|v_net| {
                    let (magnitude, sign) = v_net.magnitude_sign();

                    (
                        // magnitude is guaranteed to be an unsigned 64-bit value.
                        // Therefore, we can move it into the base field.
                        pallas::Base::from(magnitude),
                        match sign {
                            crate::value::Sign::Positive => pallas::Base::one(),
                            crate::value::Sign::Negative => -pallas::Base::one(),
                        },
                    )
                });

                let magnitude = assign_free_advice(
                    layouter.namespace(|| "v_net magnitude"),
                    config.advices[9],
                    magnitude_sign.map(|m_s| m_s.0),
                )?;
                let sign = assign_free_advice(
                    layouter.namespace(|| "v_net sign"),
                    config.advices[9],
                    magnitude_sign.map(|m_s| m_s.1),
                )?;
                (magnitude, sign)
            };

            /// 使用v_net和rcv计算value commitment cv_net
            let v_net = ScalarFixedShort::new(
                ecc_chip.clone(),
                layouter.namespace(|| "v_net"),
                v_net_magnitude_sign.clone(),
            )?;
            let rcv = ScalarFixed::new(
                ecc_chip.clone(),
                layouter.namespace(|| "rcv"),
                self.rcv.as_ref().map(|rcv| rcv.inner()),
            )?;

            let cv_net = gadget::value_commit_orchard(
                layouter.namespace(|| "cv_net = ValueCommit^Orchard_rcv(v_net)"),
                ecc_chip.clone(),
                v_net,
                rcv,
            )?;

            /// 验证计算出的cv_net等于公共输入
            // Constrain cv_net to equal public input
            layouter.constrain_instance(cv_net.inner().x().cell(), config.primary, CV_NET_X)?;
            layouter.constrain_instance(cv_net.inner().y().cell(), config.primary, CV_NET_Y)?;

            // Return the magnitude and sign so we can use them in the Orchard gate.
            v_net_magnitude_sign
        };

        /// 计算旧note的nullifier
        // Nullifier integrity (https://p.z.cash/ZKS:action-nullifier-integrity).
        let nf_old = {
            let nf_old = gadget::derive_nullifier(
                layouter.namespace(|| "nf_old = DeriveNullifier_nk(rho_old, psi_old, cm_old)"),
                config.poseidon_chip(),
                config.add_chip(),
                ecc_chip.clone(),
                rho_old.clone(),
                &psi_old,
                &cm_old,
                nk.clone(),
            )?;

            // Constrain nf_old to equal public input
            layouter.constrain_instance(nf_old.inner().cell(), config.primary, NF_OLD)?;

            nf_old
        };

        /// 计算rk = [alpha] SpendAuthG + ak_P
        // Spend authority (https://p.z.cash/ZKS:action-spend-authority)
        {
            let alpha =
                ScalarFixed::new(ecc_chip.clone(), layouter.namespace(|| "alpha"), self.alpha)?;

            // alpha_commitment = [alpha] SpendAuthG
            let (alpha_commitment, _) = {
                let spend_auth_g = OrchardFixedBasesFull::SpendAuthG;
                let spend_auth_g = FixedPoint::from_inner(ecc_chip.clone(), spend_auth_g);
                spend_auth_g.mul(layouter.namespace(|| "[alpha] SpendAuthG"), alpha)?
            };

            // [alpha] SpendAuthG + ak_P
            let rk = alpha_commitment.add(layouter.namespace(|| "rk"), &ak_P)?;

            // Constrain rk to equal public input
            layouter.constrain_instance(rk.inner().x().cell(), config.primary, RK_X)?;
            layouter.constrain_instance(rk.inner().y().cell(), config.primary, RK_Y)?;
        }

        /// 计算验证pk_d_old
        // Diversified address integrity (https://p.z.cash/ZKS:action-addr-integrity?partial).
        let pk_d_old = {
            let ivk = {
                let ak = ak_P.extract_p().inner().clone();
                let rivk = ScalarFixed::new(
                    ecc_chip.clone(),
                    layouter.namespace(|| "rivk"),
                    self.rivk.map(|rivk| rivk.inner()),
                )?;

                gadget::commit_ivk(
                    config.sinsemilla_chip_1(),
                    ecc_chip.clone(),
                    config.commit_ivk_chip(),
                    layouter.namespace(|| "CommitIvk"),
                    ak,
                    nk,
                    rivk,
                )?
            };
            let ivk =
                ScalarVar::from_base(ecc_chip.clone(), layouter.namespace(|| "ivk"), ivk.inner())?;

            // [ivk] g_d_old
            // The scalar value is passed through and discarded.
            let (derived_pk_d_old, _ivk) =
                g_d_old.mul(layouter.namespace(|| "[ivk] g_d_old"), ivk)?;

            // Constrain derived pk_d_old to equal witnessed pk_d_old
            //
            // This equality constraint is technically superfluous, because the assigned
            // value of `derived_pk_d_old` is an equivalent witness. But it's nice to see
            // an explicit connection between circuit-synthesized values, and explicit
            // prover witnesses. We could get the best of both worlds with a write-on-copy
            // abstraction (https://github.com/zcash/halo2/issues/334).
            let pk_d_old = NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| "witness pk_d_old"),
                self.pk_d_old.map(|pk_d_old| pk_d_old.inner().to_affine()),
            )?;
            derived_pk_d_old
                .constrain_equal(layouter.namespace(|| "pk_d_old equality"), &pk_d_old)?;

            pk_d_old
        };

        /// 验证计算cm_old
        // Old note commitment integrity (https://p.z.cash/ZKS:action-cm-old-integrity?partial).
        {
            let rcm_old = ScalarFixed::new(
                ecc_chip.clone(),
                layouter.namespace(|| "rcm_old"),
                self.rcm_old.as_ref().map(|rcm_old| rcm_old.inner()),
            )?;

            // g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)
            let derived_cm_old = gadget::note_commit(
                layouter.namespace(|| {
                    "g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)"
                }),
                config.sinsemilla_chip_1(),
                config.ecc_chip(),
                config.note_commit_chip_old(),
                g_d_old.inner(),
                pk_d_old.inner(),
                v_old.clone(),
                rho_old,
                psi_old,
                rcm_old,
            )?;

            // Constrain derived cm_old to equal witnessed cm_old
            derived_cm_old.constrain_equal(layouter.namespace(|| "cm_old equality"), &cm_old)?;
        }

        /// 验证计算cm_new
        // New note commitment integrity (https://p.z.cash/ZKS:action-cmx-new-integrity?partial).
        {
            // Witness g_d_new
            let g_d_new = {
                let g_d_new = self.g_d_new.map(|g_d_new| g_d_new.to_affine());
                NonIdentityPoint::new(
                    ecc_chip.clone(),
                    layouter.namespace(|| "witness g_d_new_star"),
                    g_d_new,
                )?
            };

            // Witness pk_d_new
            let pk_d_new = {
                let pk_d_new = self.pk_d_new.map(|pk_d_new| pk_d_new.inner().to_affine());
                NonIdentityPoint::new(
                    ecc_chip.clone(),
                    layouter.namespace(|| "witness pk_d_new"),
                    pk_d_new,
                )?
            };

            // ρ^new = nf^old
            let rho_new = nf_old.inner().clone();

            // Witness psi_new
            let psi_new = assign_free_advice(
                layouter.namespace(|| "witness psi_new"),
                config.advices[0],
                self.psi_new,
            )?;

            let rcm_new = ScalarFixed::new(
                ecc_chip,
                layouter.namespace(|| "rcm_new"),
                self.rcm_new.as_ref().map(|rcm_new| rcm_new.inner()),
            )?;

            // g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)
            let cm_new = gadget::note_commit(
                layouter.namespace(|| {
                    "g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)"
                }),
                config.sinsemilla_chip_2(),
                config.ecc_chip(),
                config.note_commit_chip_new(),
                g_d_new.inner(),
                pk_d_new.inner(),
                v_new.clone(),
                rho_new,
                psi_new,
                rcm_new,
            )?;

            let cmx = cm_new.extract_p();

            // Constrain cmx to equal public input
            layouter.constrain_instance(cmx.inner().cell(), config.primary, CMX)?;
        }

        /// 验证设置过程中定义的基础约束
        // Constrain the remaining Orchard circuit checks.
        layouter.assign_region(
            || "Orchard circuit checks",
            |mut region| {
                v_old.copy_advice(|| "v_old", &mut region, config.advices[0], 0)?;
                v_new.copy_advice(|| "v_new", &mut region, config.advices[1], 0)?;
                v_net_magnitude_sign.0.copy_advice(
                    || "v_net magnitude",
                    &mut region,
                    config.advices[2],
                    0,
                )?;
                v_net_magnitude_sign.1.copy_advice(
                    || "v_net sign",
                    &mut region,
                    config.advices[3],
                    0,
                )?;

                root.copy_advice(|| "calculated root", &mut region, config.advices[4], 0)?;
                region.assign_advice_from_instance(
                    || "pub input anchor",
                    config.primary,
                    ANCHOR,
                    config.advices[5],
                    0,
                )?;

                region.assign_advice_from_instance(
                    || "enable spends",
                    config.primary,
                    ENABLE_SPEND,
                    config.advices[6],
                    0,
                )?;

                region.assign_advice_from_instance(
                    || "enable outputs",
                    config.primary,
                    ENABLE_OUTPUT,
                    config.advices[7],
                    0,
                )?;

                config.q_orchard.enable(&mut region, 0)
            },
        )?;

        Ok(())
    }
}
```

曾经作为主体的`Action`现在和`Circuit`分开定义，我们可以在[zcash/orchard/src/action.rs](https://github.com/zcash/orchard/blob/main/src/action.rs)找到下面的代码，

```rust
pub struct Action<A> {
    /// The nullifier of the note being spent.
    nf: Nullifier,
    /// The randomized verification key for the note being spent.
    rk: redpallas::VerificationKey<SpendAuth>,
    /// A commitment to the new note being created.
    cmx: ExtractedNoteCommitment,
    /// The transmitted note ciphertext.
    encrypted_note: TransmittedNoteCiphertext,
    /// A commitment to the net value created or consumed by this action.
    cv_net: ValueCommitment,
    /// The authorization for this action.
    authorization: A,
}

impl<T> Action<T> {
    /// Constructs an `Action` from its constituent parts.
    pub fn from_parts(
        nf: Nullifier,
        rk: redpallas::VerificationKey<SpendAuth>,
        cmx: ExtractedNoteCommitment,
        encrypted_note: TransmittedNoteCiphertext,
        cv_net: ValueCommitment,
        authorization: T,
    ) -> Self {
        Action {
            nf,
            rk,
            cmx,
            encrypted_note,
            cv_net,
            authorization,
        }
    }

    /// Returns the nullifier of the note being spent.
    pub fn nullifier(&self) -> &Nullifier {
        &self.nf
    }

    /// Returns the randomized verification key for the note being spent.
    pub fn rk(&self) -> &redpallas::VerificationKey<SpendAuth> {
        &self.rk
    }

    /// Returns the commitment to the new note being created.
    pub fn cmx(&self) -> &ExtractedNoteCommitment {
        &self.cmx
    }

    /// Returns the encrypted note ciphertext.
    pub fn encrypted_note(&self) -> &TransmittedNoteCiphertext {
        &self.encrypted_note
    }

    /// Returns the commitment to the net value created or consumed by this action.
    pub fn cv_net(&self) -> &ValueCommitment {
        &self.cv_net
    }

    /// Returns the authorization for this action.
    pub fn authorization(&self) -> &T {
        &self.authorization
    }

    /// Transitions this action from one authorization state to another.
    pub fn map<U>(self, step: impl FnOnce(T) -> U) -> Action<U> {
        Action {
            nf: self.nf,
            rk: self.rk,
            cmx: self.cmx,
            encrypted_note: self.encrypted_note,
            cv_net: self.cv_net,
            authorization: step(self.authorization),
        }
    }

    /// Transitions this action from one authorization state to another.
    pub fn try_map<U, E>(self, step: impl FnOnce(T) -> Result<U, E>) -> Result<Action<U>, E> {
        Ok(Action {
            nf: self.nf,
            rk: self.rk,
            cmx: self.cmx,
            encrypted_note: self.encrypted_note,
            cv_net: self.cv_net,
            authorization: step(self.authorization)?,
        })
    }
}
```

`Action`在此的作用相当于Action Description，也就是公共参数和结果的载体，所以我们将重点回到集成电路`Circuit`，看一看其中使用到的芯片和工具方法。

Orchard中芯片也就是Chip的作用是，将一类使用类似参数的同大类功能组成约束库，接下来按照Circuit设置过程的顺序介绍。

#### AddChip

首先是Add芯片，它位于[zcash/orchard/src/circuit/gadget/add_chip.rs](https://github.com/zcash/orchard/blob/b448f3f4c5d65fd7bc167df3d4f73f4bb94b7806/src/circuit/gadget/add_chip.rs)，

```rust
impl AddChip {
    pub(in crate::circuit) fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
    ) -> AddConfig {
        let q_add = meta.selector();
        meta.create_gate("Field element addition: c = a + b", |meta| {
            let q_add = meta.query_selector(q_add);
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());

            Constraints::with_selector(q_add, Some(a + b - c))
        });

        AddConfig { a, b, c, q_add }
    }

    pub(in crate::circuit) fn construct(config: AddConfig) -> Self {
        Self { config }
    }
}

impl AddInstruction<pallas::Base> for AddChip {
    fn add(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        a: &AssignedCell<pallas::Base, pallas::Base>,
        b: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, plonk::Error> {
        layouter.assign_region(
            || "c = a + b",
            |mut region| {
                self.config.q_add.enable(&mut region, 0)?;

                a.copy_advice(|| "copy a", &mut region, self.config.a, 0)?;
                b.copy_advice(|| "copy b", &mut region, self.config.b, 0)?;

                let scalar_val = a.value().zip(b.value()).map(|(a, b)| a + b);
                region.assign_advice(|| "c", self.config.c, 0, || scalar_val)
            },
        )
    }
}
```

#### LookupRangeCheckConfig

其次是`LookupRangeCheckConfig`，这也是一个很简单的类库，甚至没有被定义为Chip，位于[zcash/halo2/halo2_gadgets/src/utilities/lookup_range_check.rs](https://github.com/zcash/halo2/blob/677866d65362c0de7a00120c515a9583b2da2128/halo2_gadgets/src/utilities/lookup_range_check.rs)，

```rust
impl<F: PrimeFieldBits, const K: usize> LookupRangeCheckConfig<F, K> {
    /// The `running_sum` advice column breaks the field element into `K`-bit
    /// words. It is used to construct the input expression to the lookup
    /// argument.
    ///
    /// The `table_idx` fixed column contains values from [0..2^K). Looking up
    /// a value in `table_idx` constrains it to be within this range. The table
    /// can be loaded outside this helper.
    ///
    /// # Side-effects
    ///
    /// Both the `running_sum` and `constants` columns will be equality-enabled.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        running_sum: Column<Advice>,
        table_idx: TableColumn,
    ) -> Self {
        meta.enable_equality(running_sum);

        let q_lookup = meta.complex_selector();
        let q_running = meta.complex_selector();
        let q_bitshift = meta.selector();
        let config = LookupRangeCheckConfig {
            q_lookup,
            q_running,
            q_bitshift,
            running_sum,
            table_idx,
            _marker: PhantomData,
        };

        // https://p.z.cash/halo2-0.1:decompose-combined-lookup
        meta.lookup(|meta| {
            let q_lookup = meta.query_selector(config.q_lookup);
            let q_running = meta.query_selector(config.q_running);
            let z_cur = meta.query_advice(config.running_sum, Rotation::cur());

            // In the case of a running sum decomposition, we recover the word from
            // the difference of the running sums:
            //    z_i = 2^{K}⋅z_{i + 1} + a_i
            // => a_i = z_i - 2^{K}⋅z_{i + 1}
            let running_sum_lookup = {
                let running_sum_word = {
                    let z_next = meta.query_advice(config.running_sum, Rotation::next());
                    z_cur.clone() - z_next * F::from(1 << K)
                };

                q_running.clone() * running_sum_word
            };

            // In the short range check, the word is directly witnessed.
            let short_lookup = {
                let short_word = z_cur;
                let q_short = Expression::Constant(F::ONE) - q_running;

                q_short * short_word
            };

            // Combine the running sum and short lookups:
            vec![(
                q_lookup * (running_sum_lookup + short_lookup),
                config.table_idx,
            )]
        });

        // For short lookups, check that the word has been shifted by the correct number of bits.
        // https://p.z.cash/halo2-0.1:decompose-short-lookup
        meta.create_gate("Short lookup bitshift", |meta| {
            let q_bitshift = meta.query_selector(config.q_bitshift);
            let word = meta.query_advice(config.running_sum, Rotation::prev());
            let shifted_word = meta.query_advice(config.running_sum, Rotation::cur());
            let inv_two_pow_s = meta.query_advice(config.running_sum, Rotation::next());

            let two_pow_k = F::from(1 << K);

            // shifted_word = word * 2^{K-s}
            //              = word * 2^K * inv_two_pow_s
            Constraints::with_selector(
                q_bitshift,
                Some(word * two_pow_k * inv_two_pow_s - shifted_word),
            )
        });

        config
    }

    #[cfg(test)]
    // Loads the values [0..2^K) into `table_idx`. This is only used in testing
    // for now, since the Sinsemilla chip provides a pre-loaded table in the
    // Orchard context.
    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "table_idx",
            |mut table| {
                // We generate the row values lazily (we only need them during keygen).
                for index in 0..(1 << K) {
                    table.assign_cell(
                        || "table_idx",
                        self.table_idx,
                        index,
                        || Value::known(F::from(index as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }

    /// Range check on an existing cell that is copied into this helper.
    ///
    /// Returns an error if `element` is not in a column that was passed to
    /// [`ConstraintSystem::enable_equality`] during circuit configuration.
    pub fn copy_check(
        &self,
        mut layouter: impl Layouter<F>,
        element: AssignedCell<F, F>,
        num_words: usize,
        strict: bool,
    ) -> Result<RunningSum<F>, Error> {
        layouter.assign_region(
            || format!("{:?} words range check", num_words),
            |mut region| {
                // Copy `element` and initialize running sum `z_0 = element` to decompose it.
                let z_0 = element.copy_advice(|| "z_0", &mut region, self.running_sum, 0)?;
                self.range_check(&mut region, z_0, num_words, strict)
            },
        )
    }

    /// Range check on a value that is witnessed in this helper.
    pub fn witness_check(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<F>,
        num_words: usize,
        strict: bool,
    ) -> Result<RunningSum<F>, Error> {
        layouter.assign_region(
            || "Witness element",
            |mut region| {
                let z_0 =
                    region.assign_advice(|| "Witness element", self.running_sum, 0, || value)?;
                self.range_check(&mut region, z_0, num_words, strict)
            },
        )
    }

    /// If `strict` is set to "true", the field element must fit into
    /// `num_words * K` bits. In other words, the the final cumulative sum `z_{num_words}`
    /// must be zero.
    ///
    /// If `strict` is set to "false", the final `z_{num_words}` is not constrained.
    ///
    /// `element` must have been assigned to `self.running_sum` at offset 0.
    fn range_check(
        &self,
        region: &mut Region<'_, F>,
        element: AssignedCell<F, F>,
        num_words: usize,
        strict: bool,
    ) -> Result<RunningSum<F>, Error> {
        // `num_words` must fit into a single field element.
        assert!(num_words * K <= F::CAPACITY as usize);
        let num_bits = num_words * K;

        // Chunk the first num_bits bits into K-bit words.
        let words = {
            // Take first num_bits bits of `element`.
            let bits = element.value().map(|element| {
                element
                    .to_le_bits()
                    .into_iter()
                    .take(num_bits)
                    .collect::<Vec<_>>()
            });

            bits.map(|bits| {
                bits.chunks_exact(K)
                    .map(|word| F::from(lebs2ip::<K>(&(word.try_into().unwrap()))))
                    .collect::<Vec<_>>()
            })
            .transpose_vec(num_words)
        };

        let mut zs = vec![element.clone()];

        // Assign cumulative sum such that
        //          z_i = 2^{K}⋅z_{i + 1} + a_i
        // => z_{i + 1} = (z_i - a_i) / (2^K)
        //
        // For `element` = a_0 + 2^10 a_1 + ... + 2^{120} a_{12}}, initialize z_0 = `element`.
        // If `element` fits in 130 bits, we end up with z_{13} = 0.
        let mut z = element;
        let inv_two_pow_k = F::from(1u64 << K).invert().unwrap();
        for (idx, word) in words.iter().enumerate() {
            // Enable q_lookup on this row
            self.q_lookup.enable(region, idx)?;
            // Enable q_running on this row
            self.q_running.enable(region, idx)?;

            // z_next = (z_cur - m_cur) / 2^K
            z = {
                let z_val = z
                    .value()
                    .zip(*word)
                    .map(|(z, word)| (*z - word) * inv_two_pow_k);

                // Assign z_next
                region.assign_advice(
                    || format!("z_{:?}", idx + 1),
                    self.running_sum,
                    idx + 1,
                    || z_val,
                )?
            };
            zs.push(z.clone());
        }

        if strict {
            // Constrain the final `z` to be zero.
            region.constrain_constant(zs.last().unwrap().cell(), F::ZERO)?;
        }

        Ok(RunningSum(zs))
    }

    /// Short range check on an existing cell that is copied into this helper.
    ///
    /// # Panics
    ///
    /// Panics if NUM_BITS is equal to or larger than K.
    pub fn copy_short_check(
        &self,
        mut layouter: impl Layouter<F>,
        element: AssignedCell<F, F>,
        num_bits: usize,
    ) -> Result<(), Error> {
        assert!(num_bits < K);
        layouter.assign_region(
            || format!("Range check {:?} bits", num_bits),
            |mut region| {
                // Copy `element` to use in the k-bit lookup.
                let element =
                    element.copy_advice(|| "element", &mut region, self.running_sum, 0)?;

                self.short_range_check(&mut region, element, num_bits)
            },
        )
    }

    /// Short range check on value that is witnessed in this helper.
    ///
    /// # Panics
    ///
    /// Panics if num_bits is larger than K.
    pub fn witness_short_check(
        &self,
        mut layouter: impl Layouter<F>,
        element: Value<F>,
        num_bits: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        assert!(num_bits <= K);
        layouter.assign_region(
            || format!("Range check {:?} bits", num_bits),
            |mut region| {
                // Witness `element` to use in the k-bit lookup.
                let element =
                    region.assign_advice(|| "Witness element", self.running_sum, 0, || element)?;

                self.short_range_check(&mut region, element.clone(), num_bits)?;

                Ok(element)
            },
        )
    }

    /// Constrain `x` to be a NUM_BITS word.
    ///
    /// `element` must have been assigned to `self.running_sum` at offset 0.
    fn short_range_check(
        &self,
        region: &mut Region<'_, F>,
        element: AssignedCell<F, F>,
        num_bits: usize,
    ) -> Result<(), Error> {
        // Enable lookup for `element`, to constrain it to 10 bits.
        self.q_lookup.enable(region, 0)?;

        // Enable lookup for shifted element, to constrain it to 10 bits.
        self.q_lookup.enable(region, 1)?;

        // Check element has been shifted by the correct number of bits.
        self.q_bitshift.enable(region, 1)?;

        // Assign shifted `element * 2^{K - num_bits}`
        let shifted = element.value().into_field() * F::from(1 << (K - num_bits));

        region.assign_advice(
            || format!("element * 2^({}-{})", K, num_bits),
            self.running_sum,
            1,
            || shifted,
        )?;

        // Assign 2^{-num_bits} from a fixed column.
        let inv_two_pow_s = F::from(1 << num_bits).invert().unwrap();
        region.assign_advice_from_constant(
            || format!("2^(-{})", num_bits),
            self.running_sum,
            2,
            inv_two_pow_s,
        )?;

        Ok(())
    }
}
```

#### EccChip

接着是Ecc芯片。该芯片负责验证曲线取点有效性和曲线上的计算，被用于多种密钥和value commitment的计算，我们可以在[zcash/halo2/halo2_gadgets](https://github.com/zcash/halo2/blob/476980efcdadfd532f769b599a7ea6d05eb5d362/halo2_gadgets/src/ecc/chip.rs)找到它，

```rust
impl<FixedPoints: super::FixedPoints<pallas::Affine>> EccChip<FixedPoints> {
    /// Reconstructs this chip from the given config.
    pub fn construct(config: <Self as Chip<pallas::Base>>::Config) -> Self {
        Self { config }
    }

    /// # Side effects
    ///
    /// All columns in `advices` will be equality-enabled.
    #[allow(non_snake_case)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 10],
        lagrange_coeffs: [Column<Fixed>; 8],
        range_check: LookupRangeCheckConfig<pallas::Base, { sinsemilla::K }>,
    ) -> <Self as Chip<pallas::Base>>::Config {
        // Create witness point gate
        let witness_point = witness_point::Config::configure(meta, advices[0], advices[1]);
        // Create incomplete point addition gate
        let add_incomplete =
            add_incomplete::Config::configure(meta, advices[0], advices[1], advices[2], advices[3]);

        // Create complete point addition gate
        let add = add::Config::configure(
            meta, advices[0], advices[1], advices[2], advices[3], advices[4], advices[5],
            advices[6], advices[7], advices[8],
        );

        // Create variable-base scalar mul gates
        let mul = mul::Config::configure(meta, add, range_check, advices);

        // Create config that is shared across short, base-field, and full-width
        // fixed-base scalar mul.
        let mul_fixed = mul_fixed::Config::<FixedPoints>::configure(
            meta,
            lagrange_coeffs,
            advices[4],
            advices[5],
            add,
            add_incomplete,
        );

        // Create gate that is only used in full-width fixed-base scalar mul.
        let mul_fixed_full =
            mul_fixed::full_width::Config::<FixedPoints>::configure(meta, mul_fixed.clone());

        // Create gate that is only used in short fixed-base scalar mul.
        let mul_fixed_short =
            mul_fixed::short::Config::<FixedPoints>::configure(meta, mul_fixed.clone());

        // Create gate that is only used in fixed-base mul using a base field element.
        let mul_fixed_base_field = mul_fixed::base_field_elem::Config::<FixedPoints>::configure(
            meta,
            advices[6..9].try_into().unwrap(),
            range_check,
            mul_fixed,
        );

        EccConfig {
            advices,
            add_incomplete,
            add,
            mul,
            mul_fixed_full,
            mul_fixed_short,
            mul_fixed_base_field,
            witness_point,
            lookup_config: range_check,
        }
    }
}
```

而这个芯片定义的方法就在下方，

```rust
impl<Fixed: FixedPoints<pallas::Affine>> EccInstructions<pallas::Affine> for EccChip<Fixed>
where
    <Fixed as FixedPoints<pallas::Affine>>::Base:
        FixedPoint<pallas::Affine, FixedScalarKind = BaseFieldElem>,
    <Fixed as FixedPoints<pallas::Affine>>::FullScalar:
        FixedPoint<pallas::Affine, FixedScalarKind = FullScalar>,
    <Fixed as FixedPoints<pallas::Affine>>::ShortScalar:
        FixedPoint<pallas::Affine, FixedScalarKind = ShortScalar>,
{
    type ScalarFixed = EccScalarFixed;
    type ScalarFixedShort = EccScalarFixedShort;
    type ScalarVar = ScalarVar;
    type Point = EccPoint;
    type NonIdentityPoint = NonIdentityEccPoint;
    type X = AssignedCell<pallas::Base, pallas::Base>;
    type FixedPoints = Fixed;

    fn constrain_equal(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        a: &Self::Point,
        b: &Self::Point,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "constrain equal",
            |mut region| {
                // Constrain x-coordinates
                region.constrain_equal(a.x().cell(), b.x().cell())?;
                // Constrain x-coordinates
                region.constrain_equal(a.y().cell(), b.y().cell())
            },
        )
    }

    fn witness_point(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        value: Value<pallas::Affine>,
    ) -> Result<Self::Point, Error> {
        let config = self.config().witness_point;
        layouter.assign_region(
            || "witness point",
            |mut region| config.point(value, 0, &mut region),
        )
    }

    fn witness_point_non_id(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        value: Value<pallas::Affine>,
    ) -> Result<Self::NonIdentityPoint, Error> {
        let config = self.config().witness_point;
        layouter.assign_region(
            || "witness non-identity point",
            |mut region| config.point_non_id(value, 0, &mut region),
        )
    }

    fn witness_scalar_var(
        &self,
        _layouter: &mut impl Layouter<pallas::Base>,
        _value: Value<pallas::Scalar>,
    ) -> Result<Self::ScalarVar, Error> {
        // This is unimplemented for halo2_gadgets v0.1.0.
        todo!()
    }

    fn witness_scalar_fixed(
        &self,
        _layouter: &mut impl Layouter<pallas::Base>,
        value: Value<pallas::Scalar>,
    ) -> Result<Self::ScalarFixed, Error> {
        Ok(EccScalarFixed {
            value,
            // This chip uses lazy witnessing.
            windows: None,
        })
    }

    fn scalar_fixed_from_signed_short(
        &self,
        _layouter: &mut impl Layouter<pallas::Base>,
        (magnitude, sign): MagnitudeSign,
    ) -> Result<Self::ScalarFixedShort, Error> {
        Ok(EccScalarFixedShort {
            magnitude,
            sign,
            // This chip uses lazy constraining.
            running_sum: None,
        })
    }

    fn extract_p<Point: Into<Self::Point> + Clone>(point: &Point) -> Self::X {
        let point: EccPoint = (point.clone()).into();
        point.x()
    }

    fn add_incomplete(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        a: &Self::NonIdentityPoint,
        b: &Self::NonIdentityPoint,
    ) -> Result<Self::NonIdentityPoint, Error> {
        let config = self.config().add_incomplete;
        layouter.assign_region(
            || "incomplete point addition",
            |mut region| config.assign_region(a, b, 0, &mut region),
        )
    }

    fn add<A: Into<Self::Point> + Clone, B: Into<Self::Point> + Clone>(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        a: &A,
        b: &B,
    ) -> Result<Self::Point, Error> {
        let config = self.config().add;
        layouter.assign_region(
            || "complete point addition",
            |mut region| {
                config.assign_region(&(a.clone()).into(), &(b.clone()).into(), 0, &mut region)
            },
        )
    }

    fn mul(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        scalar: &Self::ScalarVar,
        base: &Self::NonIdentityPoint,
    ) -> Result<(Self::Point, Self::ScalarVar), Error> {
        let config = self.config().mul;
        match scalar {
            ScalarVar::BaseFieldElem(scalar) => config.assign(
                layouter.namespace(|| "variable-base scalar mul"),
                scalar.clone(),
                base,
            ),
            ScalarVar::FullWidth => {
                todo!()
            }
        }
    }

    fn mul_fixed(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        scalar: &Self::ScalarFixed,
        base: &<Self::FixedPoints as FixedPoints<pallas::Affine>>::FullScalar,
    ) -> Result<(Self::Point, Self::ScalarFixed), Error> {
        let config = self.config().mul_fixed_full.clone();
        config.assign(
            layouter.namespace(|| format!("fixed-base mul of {:?}", base)),
            scalar,
            base,
        )
    }

    fn mul_fixed_short(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        scalar: &Self::ScalarFixedShort,
        base: &<Self::FixedPoints as FixedPoints<pallas::Affine>>::ShortScalar,
    ) -> Result<(Self::Point, Self::ScalarFixedShort), Error> {
        let config = self.config().mul_fixed_short.clone();
        config.assign(
            layouter.namespace(|| format!("short fixed-base mul of {:?}", base)),
            scalar,
            base,
        )
    }

    fn mul_fixed_base_field_elem(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        base_field_elem: AssignedCell<pallas::Base, pallas::Base>,
        base: &<Self::FixedPoints as FixedPoints<pallas::Affine>>::Base,
    ) -> Result<Self::Point, Error> {
        let config = self.config().mul_fixed_base_field.clone();
        config.assign(
            layouter.namespace(|| format!("base-field elem fixed-base mul of {:?}", base)),
            base_field_elem,
            base,
        )
    }
}
```

我们看到ECC芯片的设置又包含了见证点的运算`witness_point`和其他曲线上计算方法`add_incomplete`、`add`、`mul`、`mul_fixed_full`、`mul_fixed_short`、`mul_fixed_base_field`的设置，这些具体的子方法和它们的实现都位于[zcash/halo2/halo2_gadgets/src/ecc/chip](https://github.com/zcash/halo2/tree/41c87eac0f9766dc36af94291ae8537581b1272b/halo2_gadgets/src/ecc/chip)，内容比较多，这里就不贴过多的代码了。

#### PoseidonChip

然后是Poseidon芯片。这个芯片负责定义Poseidon哈希，被用于计算nullifier，我们可以在[zcash/halo2/halo2_gadgets/src/poseidon/pow5.rs](https://github.com/zcash/halo2/blob/41c87eac0f9766dc36af94291ae8537581b1272b/halo2_gadgets/src/poseidon/pow5.rs)找到它，

```rust
impl<F: Field, const WIDTH: usize, const RATE: usize> Pow5Chip<F, WIDTH, RATE> {
    /// Configures this chip for use in a circuit.
    ///
    /// # Side-effects
    ///
    /// All columns in `state` will be equality-enabled.
    //
    // TODO: Does the rate need to be hard-coded here, or only the width? It probably
    // needs to be known wherever we implement the hashing gadget, but it isn't strictly
    // necessary for the permutation.
    pub fn configure<S: Spec<F, WIDTH, RATE>>(
        meta: &mut ConstraintSystem<F>,
        state: [Column<Advice>; WIDTH],
        partial_sbox: Column<Advice>,
        rc_a: [Column<Fixed>; WIDTH],
        rc_b: [Column<Fixed>; WIDTH],
    ) -> Pow5Config<F, WIDTH, RATE> {
        assert_eq!(RATE, WIDTH - 1);
        // Generate constants for the Poseidon permutation.
        // This gadget requires R_F and R_P to be even.
        assert!(S::full_rounds() & 1 == 0);
        assert!(S::partial_rounds() & 1 == 0);
        let half_full_rounds = S::full_rounds() / 2;
        let half_partial_rounds = S::partial_rounds() / 2;
        let (round_constants, m_reg, m_inv) = S::constants();

        // This allows state words to be initialized (by constraining them equal to fixed
        // values), and used in a permutation from an arbitrary region. rc_a is used in
        // every permutation round, while rc_b is empty in the initial and final full
        // rounds, so we use rc_b as "scratch space" for fixed values (enabling potential
        // layouter optimisations).
        for column in iter::empty()
            .chain(state.iter().cloned().map(Column::<Any>::from))
            .chain(rc_b.iter().cloned().map(Column::<Any>::from))
        {
            meta.enable_equality(column);
        }

        let s_full = meta.selector();
        let s_partial = meta.selector();
        let s_pad_and_add = meta.selector();

        let alpha = [5, 0, 0, 0];
        let pow_5 = |v: Expression<F>| {
            let v2 = v.clone() * v.clone();
            v2.clone() * v2 * v
        };

        meta.create_gate("full round", |meta| {
            let s_full = meta.query_selector(s_full);

            Constraints::with_selector(
                s_full,
                (0..WIDTH)
                    .map(|next_idx| {
                        let state_next = meta.query_advice(state[next_idx], Rotation::next());
                        let expr = (0..WIDTH)
                            .map(|idx| {
                                let state_cur = meta.query_advice(state[idx], Rotation::cur());
                                let rc_a = meta.query_fixed(rc_a[idx]);
                                pow_5(state_cur + rc_a) * m_reg[next_idx][idx]
                            })
                            .reduce(|acc, term| acc + term)
                            .expect("WIDTH > 0");
                        expr - state_next
                    })
                    .collect::<Vec<_>>(),
            )
        });

        meta.create_gate("partial rounds", |meta| {
            let cur_0 = meta.query_advice(state[0], Rotation::cur());
            let mid_0 = meta.query_advice(partial_sbox, Rotation::cur());

            let rc_a0 = meta.query_fixed(rc_a[0]);
            let rc_b0 = meta.query_fixed(rc_b[0]);

            let s_partial = meta.query_selector(s_partial);

            use halo2_proofs::plonk::VirtualCells;
            let mid = |idx: usize, meta: &mut VirtualCells<F>| {
                let mid = mid_0.clone() * m_reg[idx][0];
                (1..WIDTH).fold(mid, |acc, cur_idx| {
                    let cur = meta.query_advice(state[cur_idx], Rotation::cur());
                    let rc_a = meta.query_fixed(rc_a[cur_idx]);
                    acc + (cur + rc_a) * m_reg[idx][cur_idx]
                })
            };

            let next = |idx: usize, meta: &mut VirtualCells<F>| {
                (0..WIDTH)
                    .map(|next_idx| {
                        let next = meta.query_advice(state[next_idx], Rotation::next());
                        next * m_inv[idx][next_idx]
                    })
                    .reduce(|acc, next| acc + next)
                    .expect("WIDTH > 0")
            };

            let partial_round_linear = |idx: usize, meta: &mut VirtualCells<F>| {
                let rc_b = meta.query_fixed(rc_b[idx]);
                mid(idx, meta) + rc_b - next(idx, meta)
            };

            Constraints::with_selector(
                s_partial,
                std::iter::empty()
                    // state[0] round a
                    .chain(Some(pow_5(cur_0 + rc_a0) - mid_0.clone()))
                    // state[0] round b
                    .chain(Some(pow_5(mid(0, meta) + rc_b0) - next(0, meta)))
                    .chain((1..WIDTH).map(|idx| partial_round_linear(idx, meta)))
                    .collect::<Vec<_>>(),
            )
        });

        meta.create_gate("pad-and-add", |meta| {
            let initial_state_rate = meta.query_advice(state[RATE], Rotation::prev());
            let output_state_rate = meta.query_advice(state[RATE], Rotation::next());

            let s_pad_and_add = meta.query_selector(s_pad_and_add);

            let pad_and_add = |idx: usize| {
                let initial_state = meta.query_advice(state[idx], Rotation::prev());
                let input = meta.query_advice(state[idx], Rotation::cur());
                let output_state = meta.query_advice(state[idx], Rotation::next());

                // We pad the input by storing the required padding in fixed columns and
                // then constraining the corresponding input columns to be equal to it.
                initial_state + input - output_state
            };

            Constraints::with_selector(
                s_pad_and_add,
                (0..RATE)
                    .map(pad_and_add)
                    // The capacity element is never altered by the input.
                    .chain(Some(initial_state_rate - output_state_rate))
                    .collect::<Vec<_>>(),
            )
        });

        Pow5Config {
            state,
            partial_sbox,
            rc_a,
            rc_b,
            s_full,
            s_partial,
            s_pad_and_add,
            half_full_rounds,
            half_partial_rounds,
            alpha,
            round_constants,
            m_reg,
        }
    }

    /// Construct a [`Pow5Chip`].
    pub fn construct(config: Pow5Config<F, WIDTH, RATE>) -> Self {
        Pow5Chip { config }
    }
}
```

而它定义的方法也在下方，

```rust
impl<F: Field, S: Spec<F, WIDTH, RATE>, const WIDTH: usize, const RATE: usize>
    PoseidonInstructions<F, S, WIDTH, RATE> for Pow5Chip<F, WIDTH, RATE>
{
    type Word = StateWord<F>;

    fn permute(
        &self,
        layouter: &mut impl Layouter<F>,
        initial_state: &State<Self::Word, WIDTH>,
    ) -> Result<State<Self::Word, WIDTH>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "permute state",
            |mut region| {
                // Load the initial state into this region.
                let state = Pow5State::load(&mut region, config, initial_state)?;

                let state = (0..config.half_full_rounds).fold(Ok(state), |res, r| {
                    res.and_then(|state| state.full_round(&mut region, config, r, r))
                })?;

                let state = (0..config.half_partial_rounds).fold(Ok(state), |res, r| {
                    res.and_then(|state| {
                        state.partial_round(
                            &mut region,
                            config,
                            config.half_full_rounds + 2 * r,
                            config.half_full_rounds + r,
                        )
                    })
                })?;

                let state = (0..config.half_full_rounds).fold(Ok(state), |res, r| {
                    res.and_then(|state| {
                        state.full_round(
                            &mut region,
                            config,
                            config.half_full_rounds + 2 * config.half_partial_rounds + r,
                            config.half_full_rounds + config.half_partial_rounds + r,
                        )
                    })
                })?;

                Ok(state.0)
            },
        )
    }
}

impl<
        F: Field,
        S: Spec<F, WIDTH, RATE>,
        D: Domain<F, RATE>,
        const WIDTH: usize,
        const RATE: usize,
    > PoseidonSpongeInstructions<F, S, D, WIDTH, RATE> for Pow5Chip<F, WIDTH, RATE>
{
    fn initial_state(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<State<Self::Word, WIDTH>, Error> {
        let config = self.config();
        let state = layouter.assign_region(
            || format!("initial state for domain {}", D::name()),
            |mut region| {
                let mut state = Vec::with_capacity(WIDTH);
                let mut load_state_word = |i: usize, value: F| -> Result<_, Error> {
                    let var = region.assign_advice_from_constant(
                        || format!("state_{}", i),
                        config.state[i],
                        0,
                        value,
                    )?;
                    state.push(StateWord(var));

                    Ok(())
                };

                for i in 0..RATE {
                    load_state_word(i, F::ZERO)?;
                }
                load_state_word(RATE, D::initial_capacity_element())?;

                Ok(state)
            },
        )?;

        Ok(state.try_into().unwrap())
    }

    fn add_input(
        &self,
        layouter: &mut impl Layouter<F>,
        initial_state: &State<Self::Word, WIDTH>,
        input: &Absorbing<PaddedWord<F>, RATE>,
    ) -> Result<State<Self::Word, WIDTH>, Error> {
        let config = self.config();
        layouter.assign_region(
            || format!("add input for domain {}", D::name()),
            |mut region| {
                config.s_pad_and_add.enable(&mut region, 1)?;

                // Load the initial state into this region.
                let load_state_word = |i: usize| {
                    initial_state[i]
                        .0
                        .copy_advice(
                            || format!("load state_{}", i),
                            &mut region,
                            config.state[i],
                            0,
                        )
                        .map(StateWord)
                };
                let initial_state: Result<Vec<_>, Error> =
                    (0..WIDTH).map(load_state_word).collect();
                let initial_state = initial_state?;

                // Load the input into this region.
                let load_input_word = |i: usize| {
                    let constraint_var = match input.0[i].clone() {
                        Some(PaddedWord::Message(word)) => word,
                        Some(PaddedWord::Padding(padding_value)) => region.assign_fixed(
                            || format!("load pad_{}", i),
                            config.rc_b[i],
                            1,
                            || Value::known(padding_value),
                        )?,
                        _ => panic!("Input is not padded"),
                    };
                    constraint_var
                        .copy_advice(
                            || format!("load input_{}", i),
                            &mut region,
                            config.state[i],
                            1,
                        )
                        .map(StateWord)
                };
                let input: Result<Vec<_>, Error> = (0..RATE).map(load_input_word).collect();
                let input = input?;

                // Constrain the output.
                let constrain_output_word = |i: usize| {
                    let value = initial_state[i].0.value().copied()
                        + input
                            .get(i)
                            .map(|word| word.0.value().cloned())
                            // The capacity element is never altered by the input.
                            .unwrap_or_else(|| Value::known(F::ZERO));
                    region
                        .assign_advice(
                            || format!("load output_{}", i),
                            config.state[i],
                            2,
                            || value,
                        )
                        .map(StateWord)
                };

                let output: Result<Vec<_>, Error> = (0..WIDTH).map(constrain_output_word).collect();
                output.map(|output| output.try_into().unwrap())
            },
        )
    }

    fn get_output(state: &State<Self::Word, WIDTH>) -> Squeezing<Self::Word, RATE> {
        Squeezing(
            state[..RATE]
                .iter()
                .map(|word| Some(word.clone()))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }
}
```

#### SinsemillaChip

再然后是Sinsemilla芯片。这个芯片负责定义Sinsemilla哈希，被用于note commitment和ivk的计算，我们可以在[zcash/halo2/halo2_gadgets](https://github.com/zcash/halo2/blob/476980efcdadfd532f769b599a7ea6d05eb5d362/halo2_gadgets/src/sinsemilla/chip.rs)找到它，

```rust
impl<Hash, Commit, F> SinsemillaChip<Hash, Commit, F>
where
    Hash: HashDomains<pallas::Affine>,
    F: FixedPoints<pallas::Affine>,
    Commit: CommitDomains<pallas::Affine, F, Hash>,
{
    /// Reconstructs this chip from the given config.
    pub fn construct(config: <Self as Chip<pallas::Base>>::Config) -> Self {
        Self { config }
    }

    /// Loads the lookup table required by this chip into the circuit.
    pub fn load(
        config: SinsemillaConfig<Hash, Commit, F>,
        layouter: &mut impl Layouter<pallas::Base>,
    ) -> Result<<Self as Chip<pallas::Base>>::Loaded, Error> {
        // Load the lookup table.
        config.generator_table.load(layouter)
    }

    /// # Side-effects
    ///
    /// All columns in `advices` and will be equality-enabled.
    #[allow(clippy::too_many_arguments)]
    #[allow(non_snake_case)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 5],
        witness_pieces: Column<Advice>,
        fixed_y_q: Column<Fixed>,
        lookup: (TableColumn, TableColumn, TableColumn),
        range_check: LookupRangeCheckConfig<pallas::Base, { sinsemilla::K }>,
    ) -> <Self as Chip<pallas::Base>>::Config {
        // Enable equality on all advice columns
        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        let config = SinsemillaConfig::<Hash, Commit, F> {
            q_sinsemilla1: meta.complex_selector(),
            q_sinsemilla2: meta.fixed_column(),
            q_sinsemilla4: meta.selector(),
            fixed_y_q,
            double_and_add: DoubleAndAdd {
                x_a: advices[0],
                x_p: advices[1],
                lambda_1: advices[3],
                lambda_2: advices[4],
            },
            bits: advices[2],
            witness_pieces,
            generator_table: GeneratorTableConfig {
                table_idx: lookup.0,
                table_x: lookup.1,
                table_y: lookup.2,
            },
            lookup_config: range_check,
            _marker: PhantomData,
        };

        // Set up lookup argument
        GeneratorTableConfig::configure(meta, config.clone());

        let two = pallas::Base::from(2);

        // Closures for expressions that are derived multiple times
        // x_r = lambda_1^2 - x_a - x_p
        let x_r = |meta: &mut VirtualCells<pallas::Base>, rotation| {
            config.double_and_add.x_r(meta, rotation)
        };

        // Y_A = (lambda_1 + lambda_2) * (x_a - x_r)
        let Y_A = |meta: &mut VirtualCells<pallas::Base>, rotation| {
            config.double_and_add.Y_A(meta, rotation)
        };

        // Check that the initial x_A, x_P, lambda_1, lambda_2 are consistent with y_Q.
        // https://p.z.cash/halo2-0.1:sinsemilla-constraints?partial
        meta.create_gate("Initial y_Q", |meta| {
            let q_s4 = meta.query_selector(config.q_sinsemilla4);
            let y_q = meta.query_fixed(config.fixed_y_q);

            // Y_A = (lambda_1 + lambda_2) * (x_a - x_r)
            let Y_A_cur = Y_A(meta, Rotation::cur());

            // 2 * y_q - Y_{A,0} = 0
            let init_y_q_check = y_q * two - Y_A_cur;

            Constraints::with_selector(q_s4, Some(("init_y_q_check", init_y_q_check)))
        });

        // https://p.z.cash/halo2-0.1:sinsemilla-constraints?partial
        meta.create_gate("Sinsemilla gate", |meta| {
            let q_s1 = meta.query_selector(config.q_sinsemilla1);
            let q_s3 = config.q_s3(meta);

            let lambda_1_next = meta.query_advice(config.double_and_add.lambda_1, Rotation::next());
            let lambda_2_cur = meta.query_advice(config.double_and_add.lambda_2, Rotation::cur());
            let x_a_cur = meta.query_advice(config.double_and_add.x_a, Rotation::cur());
            let x_a_next = meta.query_advice(config.double_and_add.x_a, Rotation::next());

            // x_r = lambda_1^2 - x_a_cur - x_p
            let x_r = x_r(meta, Rotation::cur());

            // Y_A = (lambda_1 + lambda_2) * (x_a - x_r)
            let Y_A_cur = Y_A(meta, Rotation::cur());

            // Y_A = (lambda_1 + lambda_2) * (x_a - x_r)
            let Y_A_next = Y_A(meta, Rotation::next());

            // lambda2^2 - (x_a_next + x_r + x_a_cur) = 0
            let secant_line =
                lambda_2_cur.clone().square() - (x_a_next.clone() + x_r + x_a_cur.clone());

            // lhs - rhs = 0, where
            //    - lhs = 4 * lambda_2_cur * (x_a_cur - x_a_next)
            //    - rhs = (2 * Y_A_cur + (2 - q_s3) * Y_A_next + 2 * q_s3 * y_a_final)
            let y_check = {
                // lhs = 4 * lambda_2_cur * (x_a_cur - x_a_next)
                let lhs = lambda_2_cur * pallas::Base::from(4) * (x_a_cur - x_a_next);

                // rhs = 2 * Y_A_cur + (2 - q_s3) * Y_A_next + 2 * q_s3 * y_a_final
                let rhs = {
                    // y_a_final is assigned to the lambda1 column on the next offset.
                    let y_a_final = lambda_1_next;

                    Y_A_cur * two
                        + (Expression::Constant(two) - q_s3.clone()) * Y_A_next
                        + q_s3 * two * y_a_final
                };
                lhs - rhs
            };

            Constraints::with_selector(q_s1, [("Secant line", secant_line), ("y check", y_check)])
        });

        config
    }
}
```

而这个芯片的方法则有SinsemillaChip和MerkleChip的两层定义，

```rust
/// SinsemillaChip
impl<Hash, Commit, F> SinsemillaInstructions<pallas::Affine, { sinsemilla::K }, { sinsemilla::C }>
    for SinsemillaChip<Hash, Commit, F>
where
    Hash: HashDomains<pallas::Affine>,
    F: FixedPoints<pallas::Affine>,
    Commit: CommitDomains<pallas::Affine, F, Hash>,
{
    type CellValue = AssignedCell<pallas::Base, pallas::Base>;

    type Message = Message<pallas::Base, { sinsemilla::K }, { sinsemilla::C }>;
    type MessagePiece = MessagePiece<pallas::Base, { sinsemilla::K }>;

    type RunningSum = Vec<Self::CellValue>;

    type X = AssignedCell<pallas::Base, pallas::Base>;
    type NonIdentityPoint = NonIdentityEccPoint;
    type FixedPoints = F;

    type HashDomains = Hash;
    type CommitDomains = Commit;

    fn witness_message_piece(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        field_elem: Value<pallas::Base>,
        num_words: usize,
    ) -> Result<Self::MessagePiece, Error> {
        let config = self.config().clone();

        let cell = layouter.assign_region(
            || "witness message piece",
            |mut region| {
                region.assign_advice(
                    || "witness message piece",
                    config.witness_pieces,
                    0,
                    || field_elem,
                )
            },
        )?;
        Ok(MessagePiece::new(cell, num_words))
    }

    #[allow(non_snake_case)]
    #[allow(clippy::type_complexity)]
    fn hash_to_point(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        Q: pallas::Affine,
        message: Self::Message,
    ) -> Result<(Self::NonIdentityPoint, Vec<Self::RunningSum>), Error> {
        layouter.assign_region(
            || "hash_to_point",
            |mut region| self.hash_message(&mut region, Q, &message),
        )
    }

    fn extract(point: &Self::NonIdentityPoint) -> Self::X {
        point.x()
    }
}
```

#### MerkleChip

`MerkleChip`可以被认为是继承了`SinsemillaChip`，我们在[](https://github.com/zcash/halo2/blob/677866d65362c0de7a00120c515a9583b2da2128/halo2_gadgets/src/sinsemilla/merkle/chip.rs)找到它，

```rust
impl<Hash, Commit, F> MerkleChip<Hash, Commit, F>
where
    Hash: HashDomains<pallas::Affine>,
    F: FixedPoints<pallas::Affine>,
    Commit: CommitDomains<pallas::Affine, F, Hash>,
{
    /// Configures the [`MerkleChip`].
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        sinsemilla_config: SinsemillaConfig<Hash, Commit, F>,
    ) -> MerkleConfig<Hash, Commit, F> {
        // All five advice columns are equality-enabled by SinsemillaConfig.
        let advices = sinsemilla_config.advices();
        let cond_swap_config = CondSwapChip::configure(meta, advices);

        // This selector enables the decomposition gate.
        let q_decompose = meta.selector();

        // Check that pieces have been decomposed correctly for Sinsemilla hash.
        // <https://zips.z.cash/protocol/protocol.pdf#orchardmerklecrh>
        //
        // a = a_0||a_1 = l || (bits 0..=239 of left)
        // b = b_0||b_1||b_2
        //   = (bits 240..=249 of left) || (bits 250..=254 of left) || (bits 0..=4 of right)
        // c = bits 5..=254 of right
        //
        // The message pieces `a`, `b`, `c` are constrained by Sinsemilla to be
        // 250 bits, 20 bits, and 250 bits respectively.
        //
        // The pieces and subpieces are arranged in the following configuration:
        // |  A_0  |  A_1  |  A_2  |  A_3  |  A_4  | q_decompose |
        // -------------------------------------------------------
        // |   a   |   b   |   c   |  left | right |      1      |
        // |  z1_a |  z1_b |  b_1  |  b_2  |   l   |      0      |
        meta.create_gate("Decomposition check", |meta| {
            let q_decompose = meta.query_selector(q_decompose);
            let l_whole = meta.query_advice(advices[4], Rotation::next());

            let two_pow_5 = pallas::Base::from(1 << 5);
            let two_pow_10 = two_pow_5.square();

            // a_whole is constrained by Sinsemilla to be 250 bits.
            let a_whole = meta.query_advice(advices[0], Rotation::cur());
            // b_whole is constrained by Sinsemilla to be 20 bits.
            let b_whole = meta.query_advice(advices[1], Rotation::cur());
            // c_whole is constrained by Sinsemilla to be 250 bits.
            let c_whole = meta.query_advice(advices[2], Rotation::cur());
            let left_node = meta.query_advice(advices[3], Rotation::cur());
            let right_node = meta.query_advice(advices[4], Rotation::cur());

            // a = a_0||a_1 = l || (bits 0..=239 of left)
            //
            // z_1 of SinsemillaHash(a) = a_1
            // => a_0 = a - (a_1 * 2^10)
            let z1_a = meta.query_advice(advices[0], Rotation::next());
            let a_1 = z1_a;
            // Derive a_0 (constrained by SinsemillaHash to be 10 bits)
            let a_0 = a_whole - a_1.clone() * two_pow_10;

            // b = b_0||b_1||b_2
            //   = (bits 240..=249 of left) || (bits 250..=254 of left) || (bits 0..=4 of right)
            // The Orchard specification allows this representation to be non-canonical.
            // <https://zips.z.cash/protocol/protocol.pdf#merklepath>
            //
            //    z_1 of SinsemillaHash(b) = b_1 + 2^5 b_2
            // => b_0 = b - (z1_b * 2^10)
            let z1_b = meta.query_advice(advices[1], Rotation::next());
            // b_1 has been constrained to be 5 bits outside this gate.
            let b_1 = meta.query_advice(advices[2], Rotation::next());
            // b_2 has been constrained to be 5 bits outside this gate.
            let b_2 = meta.query_advice(advices[3], Rotation::next());
            // Constrain b_1 + 2^5 b_2 = z1_b
            // https://p.z.cash/halo2-0.1:sinsemilla-merkle-crh-bit-lengths?partial
            let b1_b2_check = z1_b.clone() - (b_1.clone() + b_2.clone() * two_pow_5);
            // Derive b_0 (constrained by SinsemillaHash to be 10 bits)
            let b_0 = b_whole - (z1_b * two_pow_10);

            // Check that left = a_1 (240 bits) || b_0 (10 bits) || b_1 (5 bits)
            // https://p.z.cash/halo2-0.1:sinsemilla-merkle-crh-decomposition?partial
            let left_check = {
                let reconstructed = {
                    let two_pow_240 = pallas::Base::from_u128(1 << 120).square();
                    a_1 + (b_0 + b_1 * two_pow_10) * two_pow_240
                };
                reconstructed - left_node
            };

            // Check that right = b_2 (5 bits) || c (250 bits)
            // The Orchard specification allows this representation to be non-canonical.
            // <https://zips.z.cash/protocol/protocol.pdf#merklepath>
            // https://p.z.cash/halo2-0.1:sinsemilla-merkle-crh-decomposition?partial
            let right_check = b_2 + c_whole * two_pow_5 - right_node;

            Constraints::with_selector(
                q_decompose,
                [
                    ("l_check", a_0 - l_whole),
                    ("left_check", left_check),
                    ("right_check", right_check),
                    ("b1_b2_check", b1_b2_check),
                ],
            )
        });

        MerkleConfig {
            advices,
            q_decompose,
            cond_swap_config,
            sinsemilla_config,
        }
    }

    /// Constructs a [`MerkleChip`] given a [`MerkleConfig`].
    pub fn construct(config: MerkleConfig<Hash, Commit, F>) -> Self {
        MerkleChip { config }
    }
}
```

它不仅重写了SinsemillaChip的方法，

```rust
impl<Hash, Commit, F> SinsemillaInstructions<pallas::Affine, { sinsemilla::K }, { sinsemilla::C }>
    for MerkleChip<Hash, Commit, F>
where
    Hash: HashDomains<pallas::Affine>,
    F: FixedPoints<pallas::Affine>,
    Commit: CommitDomains<pallas::Affine, F, Hash>,
{
    type CellValue = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::CellValue;

    type Message = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::Message;
    type MessagePiece = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::MessagePiece;
    type RunningSum = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::RunningSum;

    type X = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::X;
    type NonIdentityPoint = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::NonIdentityPoint;
    type FixedPoints = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::FixedPoints;

    type HashDomains = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::HashDomains;
    type CommitDomains = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::CommitDomains;

    fn witness_message_piece(
        &self,
        layouter: impl Layouter<pallas::Base>,
        value: Value<pallas::Base>,
        num_words: usize,
    ) -> Result<Self::MessagePiece, Error> {
        let config = self.config().sinsemilla_config.clone();
        let chip = SinsemillaChip::<Hash, Commit, F>::construct(config);
        chip.witness_message_piece(layouter, value, num_words)
    }

    #[allow(non_snake_case)]
    #[allow(clippy::type_complexity)]
    fn hash_to_point(
        &self,
        layouter: impl Layouter<pallas::Base>,
        Q: pallas::Affine,
        message: Self::Message,
    ) -> Result<(Self::NonIdentityPoint, Vec<Vec<Self::CellValue>>), Error> {
        let config = self.config().sinsemilla_config.clone();
        let chip = SinsemillaChip::<Hash, Commit, F>::construct(config);
        chip.hash_to_point(layouter, Q, message)
    }

    fn extract(point: &Self::NonIdentityPoint) -> Self::X {
        SinsemillaChip::<Hash, Commit, F>::extract(point)
    }
}
```

并且提供了自己的方法，

```rust
impl<Hash, Commit, F, const MERKLE_DEPTH: usize>
    MerkleInstructions<pallas::Affine, MERKLE_DEPTH, { sinsemilla::K }, { sinsemilla::C }>
    for MerkleChip<Hash, Commit, F>
where
    Hash: HashDomains<pallas::Affine> + Eq,
    F: FixedPoints<pallas::Affine>,
    Commit: CommitDomains<pallas::Affine, F, Hash> + Eq,
{
    #[allow(non_snake_case)]
    fn hash_layer(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        Q: pallas::Affine,
        // l = MERKLE_DEPTH - layer - 1
        l: usize,
        left: Self::Var,
        right: Self::Var,
    ) -> Result<Self::Var, Error> {
        let config = self.config().clone();

        // We need to hash `l || left || right`, where `l` is a 10-bit value.
        // We allow `left` and `right` to be non-canonical 255-bit encodings.
        //
        // a = a_0||a_1 = l || (bits 0..=239 of left)
        // b = b_0||b_1||b_2
        //   = (bits 240..=249 of left) || (bits 250..=254 of left) || (bits 0..=4 of right)
        // c = bits 5..=254 of right
        //
        // We start by witnessing all of the individual pieces, and range-constraining the
        // short pieces b_1 and b_2.
        //
        // https://p.z.cash/halo2-0.1:sinsemilla-merkle-crh-bit-lengths?partial

        // `a = a_0||a_1` = `l` || (bits 0..=239 of `left`)
        let a = MessagePiece::from_subpieces(
            self.clone(),
            layouter.namespace(|| "Witness a = a_0 || a_1"),
            [
                RangeConstrained::bitrange_of(Value::known(&pallas::Base::from(l as u64)), 0..10),
                RangeConstrained::bitrange_of(left.value(), 0..240),
            ],
        )?;

        // b = b_0 || b_1 || b_2
        //   = (bits 240..=249 of left) || (bits 250..=254 of left) || (bits 0..=4 of right)
        let (b_1, b_2, b) = {
            // b_0 = (bits 240..=249 of `left`)
            let b_0 = RangeConstrained::bitrange_of(left.value(), 240..250);

            // b_1 = (bits 250..=254 of `left`)
            // Constrain b_1 to 5 bits.
            let b_1 = RangeConstrained::witness_short(
                &config.sinsemilla_config.lookup_config(),
                layouter.namespace(|| "b_1"),
                left.value(),
                250..(pallas::Base::NUM_BITS as usize),
            )?;

            // b_2 = (bits 0..=4 of `right`)
            // Constrain b_2 to 5 bits.
            let b_2 = RangeConstrained::witness_short(
                &config.sinsemilla_config.lookup_config(),
                layouter.namespace(|| "b_2"),
                right.value(),
                0..5,
            )?;

            let b = MessagePiece::from_subpieces(
                self.clone(),
                layouter.namespace(|| "Witness b = b_0 || b_1 || b_2"),
                [b_0, b_1.value(), b_2.value()],
            )?;

            (b_1, b_2, b)
        };

        // c = bits 5..=254 of `right`
        let c = MessagePiece::from_subpieces(
            self.clone(),
            layouter.namespace(|| "Witness c"),
            [RangeConstrained::bitrange_of(
                right.value(),
                5..(pallas::Base::NUM_BITS as usize),
            )],
        )?;

        // hash = SinsemillaHash(Q, 𝑙⋆ || left⋆ || right⋆)
        //
        // `hash = ⊥` is handled internally to `SinsemillaChip::hash_to_point`: incomplete
        // addition constraints allows ⊥ to occur, and then during synthesis it detects
        // these edge cases and raises an error (aborting proof creation).
        //
        // Note that MerkleCRH as-defined maps ⊥ to 0. This is for completeness outside
        // the circuit (so that the ⊥ does not propagate into the type system). The chip
        // explicitly doesn't map ⊥ to 0; in fact it cannot, as doing so would require
        // constraints that amount to using complete addition. The rationale for excluding
        // this map is the same as why Sinsemilla uses incomplete addition: this situation
        // yields a nontrivial discrete log relation, and by assumption it is hard to find
        // these.
        //
        // https://p.z.cash/proto:merkle-crh-orchard
        let (point, zs) = self.hash_to_point(
            layouter.namespace(|| format!("hash at l = {}", l)),
            Q,
            vec![a.inner(), b.inner(), c.inner()].into(),
        )?;
        let hash = Self::extract(&point);

        // `SinsemillaChip::hash_to_point` returns the running sum for each `MessagePiece`.
        // Grab the outputs we need for the decomposition constraints.
        let z1_a = zs[0][1].clone();
        let z1_b = zs[1][1].clone();

        // Check that the pieces have been decomposed properly.
        //
        // The pieces and subpieces are arranged in the following configuration:
        // |  A_0  |  A_1  |  A_2  |  A_3  |  A_4  | q_decompose |
        // -------------------------------------------------------
        // |   a   |   b   |   c   |  left | right |      1      |
        // |  z1_a |  z1_b |  b_1  |  b_2  |   l   |      0      |
        {
            layouter.assign_region(
                || "Check piece decomposition",
                |mut region| {
                    // Set the fixed column `l` to the current l.
                    // Recall that l = MERKLE_DEPTH - layer - 1.
                    // The layer with 2^n nodes is called "layer n".
                    config.q_decompose.enable(&mut region, 0)?;
                    region.assign_advice_from_constant(
                        || format!("l {}", l),
                        config.advices[4],
                        1,
                        pallas::Base::from(l as u64),
                    )?;

                    // Offset 0
                    // Copy and assign `a` at the correct position.
                    a.inner().cell_value().copy_advice(
                        || "copy a",
                        &mut region,
                        config.advices[0],
                        0,
                    )?;
                    // Copy and assign `b` at the correct position.
                    b.inner().cell_value().copy_advice(
                        || "copy b",
                        &mut region,
                        config.advices[1],
                        0,
                    )?;
                    // Copy and assign `c` at the correct position.
                    c.inner().cell_value().copy_advice(
                        || "copy c",
                        &mut region,
                        config.advices[2],
                        0,
                    )?;
                    // Copy and assign the left node at the correct position.
                    left.copy_advice(|| "left", &mut region, config.advices[3], 0)?;
                    // Copy and assign the right node at the correct position.
                    right.copy_advice(|| "right", &mut region, config.advices[4], 0)?;

                    // Offset 1
                    // Copy and assign z_1 of SinsemillaHash(a) = a_1
                    z1_a.copy_advice(|| "z1_a", &mut region, config.advices[0], 1)?;
                    // Copy and assign z_1 of SinsemillaHash(b) = b_1
                    z1_b.copy_advice(|| "z1_b", &mut region, config.advices[1], 1)?;
                    // Copy `b_1`, which has been constrained to be a 5-bit value
                    b_1.inner()
                        .copy_advice(|| "b_1", &mut region, config.advices[2], 1)?;
                    // Copy `b_2`, which has been constrained to be a 5-bit value
                    b_2.inner()
                        .copy_advice(|| "b_2", &mut region, config.advices[3], 1)?;

                    Ok(())
                },
            )?;
        }

        // Check layer hash output against Sinsemilla primitives hash
        #[cfg(test)]
        {
            use crate::{sinsemilla::primitives::HashDomain, utilities::i2lebsp};

            use group::ff::PrimeFieldBits;

            left.value()
                .zip(right.value())
                .zip(hash.value())
                .assert_if_known(|((left, right), hash)| {
                    let l = i2lebsp::<10>(l as u64);
                    let left: Vec<_> = left
                        .to_le_bits()
                        .iter()
                        .by_vals()
                        .take(pallas::Base::NUM_BITS as usize)
                        .collect();
                    let right: Vec<_> = right
                        .to_le_bits()
                        .iter()
                        .by_vals()
                        .take(pallas::Base::NUM_BITS as usize)
                        .collect();
                    let merkle_crh = HashDomain::from_Q(Q.into());

                    let mut message = l.to_vec();
                    message.extend_from_slice(&left);
                    message.extend_from_slice(&right);

                    let expected = merkle_crh.hash(message.into_iter()).unwrap();

                    expected.to_repr() == hash.to_repr()
                });
        }

        Ok(hash)
    }
}
```

#### CommitIvkChip

接下来看到CommitIvk芯片。该芯片已经是一个半集成的电路，因为它来自[zcash/orchard](https://github.com/zcash/orchard/blob/b448f3f4c5d65fd7bc167df3d4f73f4bb94b7806/src/circuit/commit_ivk.rs)而非zcash/halo2，

```rust
impl CommitIvkChip {
    pub(in crate::circuit) fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 10],
    ) -> CommitIvkConfig {
        let q_commit_ivk = meta.selector();

        let config = CommitIvkConfig {
            q_commit_ivk,
            advices,
        };

        // <https://zips.z.cash/protocol/nu5.pdf#concretesinsemillacommit>
        // We need to hash `ak || nk` where each of `ak`, `nk` is a field element (255 bits).
        //
        // a = bits 0..=249 of `ak`
        // b = b_0||b_1||b_2`
        //   = (bits 250..=253 of `ak`) || (bit 254 of  `ak`) || (bits 0..=4 of  `nk`)
        // c = bits 5..=244 of `nk`
        // d = d_0||d_1` = (bits 245..=253 of `nk`) || (bit 254 of `nk`)
        //
        // `a`, `b`, `c`, `d` have been constrained by the Sinsemilla hash to be:
        //   - a: 250 bits,
        //   - b: 10 bits,
        //   - c: 240 bits,
        //   - d: 10 bits
        //
        // https://p.z.cash/orchard-0.1:commit-ivk-decompositions
        // https://p.z.cash/orchard-0.1:commit-ivk-region-layout?partial
        /*
            The pieces are laid out in this configuration:
            |  A_0  |  A_1  |  A_2  |  A_3  |  A_4  |  A_5  |  A_6  |    A_7    |       A_8      | q_commit_ivk |
            -----------------------------------------------------------------------------------------------------
            |   ak  |   a   |   b   |  b_0  |  b_1  |  b_2  | z13_a |  a_prime  |   z13_a_prime  |       1      |
            |   nk  |   c   |   d   |  d_0  |  d_1  |       | z13_c | b2_c_prime| z14_b2_c_prime |       0      |
        */
        meta.create_gate("CommitIvk canonicity check", |meta| {
            let q_commit_ivk = meta.query_selector(config.q_commit_ivk);

            // Useful constants
            let two_pow_4 = pallas::Base::from(1 << 4);
            let two_pow_5 = pallas::Base::from(1 << 5);
            let two_pow_9 = two_pow_4 * two_pow_5;
            let two_pow_250 = pallas::Base::from_u128(1 << 125).square();
            let two_pow_254 = two_pow_250 * two_pow_4;

            let ak = meta.query_advice(config.advices[0], Rotation::cur());
            let nk = meta.query_advice(config.advices[0], Rotation::next());

            // `a` is constrained by the Sinsemilla hash to be 250 bits.
            let a = meta.query_advice(config.advices[1], Rotation::cur());
            // `b` is constrained by the Sinsemilla hash to be 10 bits.
            let b_whole = meta.query_advice(config.advices[2], Rotation::cur());
            // `c` is constrained by the Sinsemilla hash to be 240 bits.
            let c = meta.query_advice(config.advices[1], Rotation::next());
            // `d` is constrained by the Sinsemilla hash to be 10 bits.
            let d_whole = meta.query_advice(config.advices[2], Rotation::next());

            // b = b_0||b_1||b_2`
            //   = (bits 250..=253 of `ak`) || (bit 254 of  `ak`) || (bits 0..=4 of  `nk`)
            //
            // b_0 has been constrained outside this gate to be a four-bit value.
            let b_0 = meta.query_advice(config.advices[3], Rotation::cur());
            // This gate constrains b_1 to be a one-bit value.
            let b_1 = meta.query_advice(config.advices[4], Rotation::cur());
            // b_2 has been constrained outside this gate to be a five-bit value.
            let b_2 = meta.query_advice(config.advices[5], Rotation::cur());
            // Check that b_whole is consistent with the witnessed subpieces.
            let b_decomposition_check =
                b_whole - (b_0.clone() + b_1.clone() * two_pow_4 + b_2.clone() * two_pow_5);

            // d = d_0||d_1` = (bits 245..=253 of `nk`) || (bit 254 of `nk`)
            //
            // d_0 has been constrained outside this gate to be a nine-bit value.
            let d_0 = meta.query_advice(config.advices[3], Rotation::next());
            // This gate constrains d_1 to be a one-bit value.
            let d_1 = meta.query_advice(config.advices[4], Rotation::next());
            // Check that d_whole is consistent with the witnessed subpieces.
            let d_decomposition_check = d_whole - (d_0.clone() + d_1.clone() * two_pow_9);

            // Check `b_1` and `d_1` are each a single-bit value.
            // https://p.z.cash/orchard-0.1:commit-ivk-bit-lengths?partial
            let b1_bool_check = bool_check(b_1.clone());
            let d1_bool_check = bool_check(d_1.clone());

            // Check that ak = a (250 bits) || b_0 (4 bits) || b_1 (1 bit)
            let ak_decomposition_check =
                a.clone() + b_0.clone() * two_pow_250 + b_1.clone() * two_pow_254 - ak;

            // Check that nk = b_2 (5 bits) || c (240 bits) || d_0 (9 bits) || d_1 (1 bit)
            let nk_decomposition_check = {
                let two_pow_245 = pallas::Base::from(1 << 49).pow(&[5, 0, 0, 0]);

                b_2.clone()
                    + c.clone() * two_pow_5
                    + d_0.clone() * two_pow_245
                    + d_1.clone() * two_pow_254
                    - nk
            };

            // ak = a (250 bits) || b_0 (4 bits) || b_1 (1 bit)
            // The `ak` canonicity checks are enforced if and only if `b_1` = 1.
            // https://p.z.cash/orchard-0.1:commit-ivk-canonicity-ak?partial
            let ak_canonicity_checks = {
                // b_1 = 1 => b_0 = 0
                let b0_canon_check = b_1.clone() * b_0;

                // z13_a is the 13th running sum output by the 10-bit Sinsemilla decomposition of `a`.
                // b_1 = 1 => z13_a = 0
                let z13_a_check = {
                    let z13_a = meta.query_advice(config.advices[6], Rotation::cur());
                    b_1.clone() * z13_a
                };

                // Check that a_prime = a + 2^130 - t_P.
                // This is checked regardless of the value of b_1.
                let a_prime_check = {
                    let a_prime = meta.query_advice(config.advices[7], Rotation::cur());
                    let two_pow_130 =
                        Expression::Constant(pallas::Base::from_u128(1 << 65).square());
                    let t_p = Expression::Constant(pallas::Base::from_u128(T_P));
                    a + two_pow_130 - t_p - a_prime
                };

                // Check that the running sum output by the 130-bit little-endian decomposition of
                // `a_prime` is zero.
                let z13_a_prime = {
                    let z13_a_prime = meta.query_advice(config.advices[8], Rotation::cur());
                    b_1 * z13_a_prime
                };

                iter::empty()
                    .chain(Some(("b0_canon_check", b0_canon_check)))
                    .chain(Some(("z13_a_check", z13_a_check)))
                    .chain(Some(("a_prime_check", a_prime_check)))
                    .chain(Some(("z13_a_prime", z13_a_prime)))
            };

            // nk = b_2 (5 bits) || c (240 bits) || d_0 (9 bits) || d_1 (1 bit)
            // The `nk` canonicity checks are enforced if and only if `d_1` = 1.
            // https://p.z.cash/orchard-0.1:commit-ivk-canonicity-nk?partial
            let nk_canonicity_checks = {
                // d_1 = 1 => d_0 = 0
                let c0_canon_check = d_1.clone() * d_0;

                // d_1 = 1 => z13_c = 0, where z13_c is the 13th running sum
                // output by the 10-bit Sinsemilla decomposition of `c`.
                let z13_c_check = {
                    let z13_c = meta.query_advice(config.advices[6], Rotation::next());
                    d_1.clone() * z13_c
                };

                // Check that b2_c_prime = b_2 + c * 2^5 + 2^140 - t_P.
                // This is checked regardless of the value of d_1.
                let b2_c_prime_check = {
                    let two_pow_5 = pallas::Base::from(1 << 5);
                    let two_pow_140 =
                        Expression::Constant(pallas::Base::from_u128(1 << 70).square());
                    let t_p = Expression::Constant(pallas::Base::from_u128(T_P));
                    let b2_c_prime = meta.query_advice(config.advices[7], Rotation::next());
                    b_2 + c * two_pow_5 + two_pow_140 - t_p - b2_c_prime
                };

                // Check that the running sum output by the 140-bit little-
                // endian decomposition of b2_c_prime is zero.
                let z14_b2_c_prime = {
                    let z14_b2_c_prime = meta.query_advice(config.advices[8], Rotation::next());
                    d_1 * z14_b2_c_prime
                };

                iter::empty()
                    .chain(Some(("c0_canon_check", c0_canon_check)))
                    .chain(Some(("z13_c_check", z13_c_check)))
                    .chain(Some(("b2_c_prime_check", b2_c_prime_check)))
                    .chain(Some(("z14_b2_c_prime", z14_b2_c_prime)))
            };

            Constraints::with_selector(
                q_commit_ivk,
                iter::empty()
                    .chain(Some(("b1_bool_check", b1_bool_check)))
                    .chain(Some(("d1_bool_check", d1_bool_check)))
                    .chain(Some(("b_decomposition_check", b_decomposition_check)))
                    .chain(Some(("d_decomposition_check", d_decomposition_check)))
                    .chain(Some(("ak_decomposition_check", ak_decomposition_check)))
                    .chain(Some(("nk_decomposition_check", nk_decomposition_check)))
                    .chain(ak_canonicity_checks)
                    .chain(nk_canonicity_checks),
            )
        });

        config
    }

    pub(in crate::circuit) fn construct(config: CommitIvkConfig) -> Self {
        Self { config }
    }
}
```

该芯片只提供了参数的验证约束，而它的方法都是对其他芯片的组合调用，

```rust
pub(in crate::circuit) mod gadgets {
    use halo2_gadgets::utilities::{lookup_range_check::LookupRangeCheckConfig, RangeConstrained};
    use halo2_proofs::circuit::Chip;

    use super::*;

    /// `Commit^ivk` from [Section 5.4.8.4 Sinsemilla commitments].
    ///
    /// [Section 5.4.8.4 Sinsemilla commitments]: https://zips.z.cash/protocol/protocol.pdf#concretesinsemillacommit
    #[allow(non_snake_case)]
    #[allow(clippy::type_complexity)]
    pub(in crate::circuit) fn commit_ivk(
        sinsemilla_chip: SinsemillaChip<
            OrchardHashDomains,
            OrchardCommitDomains,
            OrchardFixedBases,
        >,
        ecc_chip: EccChip<OrchardFixedBases>,
        commit_ivk_chip: CommitIvkChip,
        mut layouter: impl Layouter<pallas::Base>,
        ak: AssignedCell<pallas::Base, pallas::Base>,
        nk: AssignedCell<pallas::Base, pallas::Base>,
        rivk: ScalarFixed<pallas::Affine, EccChip<OrchardFixedBases>>,
    ) -> Result<X<pallas::Affine, EccChip<OrchardFixedBases>>, Error> {
        let lookup_config = sinsemilla_chip.config().lookup_config();

        // We need to hash `ak || nk` where each of `ak`, `nk` is a field element (255 bits).
        //
        // a = bits 0..=249 of `ak`
        // b = b_0||b_1||b_2`
        //   = (bits 250..=253 of `ak`) || (bit 254 of  `ak`) || (bits 0..=4 of  `nk`)
        // c = bits 5..=244 of `nk`
        // d = d_0||d_1` = (bits 245..=253 of `nk`) || (bit 254 of `nk`)
        //
        // We start by witnessing all of the individual pieces, and range-constraining
        // the short pieces b_0, b_2, and d_0.
        //
        // https://p.z.cash/orchard-0.1:commit-ivk-bit-lengths?partial

        // `a` = bits 0..=249 of `ak`
        let a = MessagePiece::from_subpieces(
            sinsemilla_chip.clone(),
            layouter.namespace(|| "a"),
            [RangeConstrained::bitrange_of(ak.value(), 0..250)],
        )?;

        // `b = b_0||b_1||b_2`
        //    = (bits 250..=253 of `ak`) || (bit 254 of  `ak`) || (bits 0..=4 of  `nk`)
        let (b_0, b_1, b_2, b) = {
            // Constrain b_0 to be 4 bits.
            let b_0 = RangeConstrained::witness_short(
                &lookup_config,
                layouter.namespace(|| "b_0"),
                ak.value(),
                250..254,
            )?;
            // b_1 will be boolean-constrained in the custom gate.
            let b_1 = RangeConstrained::bitrange_of(ak.value(), 254..255);
            // Constrain b_2 to be 5 bits.
            let b_2 = RangeConstrained::witness_short(
                &lookup_config,
                layouter.namespace(|| "b_2"),
                nk.value(),
                0..5,
            )?;

            let b = MessagePiece::from_subpieces(
                sinsemilla_chip.clone(),
                layouter.namespace(|| "b = b_0 || b_1 || b_2"),
                [b_0.value(), b_1, b_2.value()],
            )?;

            (b_0, b_1, b_2, b)
        };

        // c = bits 5..=244 of `nk`
        let c = MessagePiece::from_subpieces(
            sinsemilla_chip.clone(),
            layouter.namespace(|| "c"),
            [RangeConstrained::bitrange_of(nk.value(), 5..245)],
        )?;

        // `d = d_0||d_1` = (bits 245..=253 of `nk`) || (bit 254 of `nk`)
        let (d_0, d_1, d) = {
            // Constrain d_0 to be 9 bits.
            let d_0 = RangeConstrained::witness_short(
                &lookup_config,
                layouter.namespace(|| "d_0"),
                nk.value(),
                245..254,
            )?;
            // d_1 will be boolean-constrained in the custom gate.
            let d_1 = RangeConstrained::bitrange_of(nk.value(), 254..255);

            let d = MessagePiece::from_subpieces(
                sinsemilla_chip.clone(),
                layouter.namespace(|| "d = d_0 || d_1"),
                [d_0.value(), d_1],
            )?;

            (d_0, d_1, d)
        };

        // ivk = Commit^ivk_rivk(I2LEBSP_255(ak) || I2LEBSP_255(nk))
        //
        // `ivk = ⊥` is handled internally to `CommitDomain::short_commit`: incomplete
        // addition constraints allows ⊥ to occur, and then during synthesis it detects
        // these edge cases and raises an error (aborting proof creation).
        //
        // https://p.z.cash/ZKS:action-addr-integrity?partial
        let (ivk, zs) = {
            let message = Message::from_pieces(
                sinsemilla_chip.clone(),
                vec![a.clone(), b.clone(), c.clone(), d.clone()],
            );
            let domain =
                CommitDomain::new(sinsemilla_chip, ecc_chip, &OrchardCommitDomains::CommitIvk);
            domain.short_commit(layouter.namespace(|| "Hash ak||nk"), message, rivk)?
        };

        // `CommitDomain::short_commit` returns the running sum for each `MessagePiece`.
        // Grab the outputs for pieces `a` and `c` that we will need for canonicity checks
        // on `ak` and `nk`.
        let z13_a = zs[0][13].clone();
        let z13_c = zs[2][13].clone();

        let (a_prime, z13_a_prime) = ak_canonicity(
            &lookup_config,
            layouter.namespace(|| "ak canonicity"),
            a.inner().cell_value(),
        )?;

        let (b2_c_prime, z14_b2_c_prime) = nk_canonicity(
            &lookup_config,
            layouter.namespace(|| "nk canonicity"),
            &b_2,
            c.inner().cell_value(),
        )?;

        let gate_cells = GateCells {
            a: a.inner().cell_value(),
            b: b.inner().cell_value(),
            c: c.inner().cell_value(),
            d: d.inner().cell_value(),
            ak,
            nk,
            b_0,
            b_1,
            b_2,
            d_0,
            d_1,
            z13_a,
            a_prime,
            z13_a_prime,
            z13_c,
            b2_c_prime,
            z14_b2_c_prime,
        };

        commit_ivk_chip.config.assign_gate(
            layouter.namespace(|| "Assign cells used in canonicity gate"),
            gate_cells,
        )?;

        Ok(ivk)
    }

    /// Witnesses and decomposes the `a'` value we need to check the canonicity of `ak`.
    ///
    /// [Specification](https://p.z.cash/orchard-0.1:commit-ivk-canonicity-ak?partial).
    #[allow(clippy::type_complexity)]
    fn ak_canonicity(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        mut layouter: impl Layouter<pallas::Base>,
        a: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            AssignedCell<pallas::Base, pallas::Base>,
            AssignedCell<pallas::Base, pallas::Base>,
        ),
        Error,
    > {
        // `ak` = `a (250 bits) || b_0 (4 bits) || b_1 (1 bit)`
        // - b_1 = 1 => b_0 = 0
        // - b_1 = 1 => a < t_P
        //     - (0 ≤ a < 2^130) => z13_a of SinsemillaHash(a) == 0
        //     - 0 ≤ a + 2^130 - t_P < 2^130 (thirteen 10-bit lookups)

        // Decompose the low 130 bits of a_prime = a + 2^130 - t_P, and output
        // the running sum at the end of it. If a_prime < 2^130, the running sum
        // will be 0.
        let a_prime = {
            let two_pow_130 = Value::known(pallas::Base::from_u128(1u128 << 65).square());
            let t_p = Value::known(pallas::Base::from_u128(T_P));
            a.value() + two_pow_130 - t_p
        };
        let zs = lookup_config.witness_check(
            layouter.namespace(|| "Decompose low 130 bits of (a + 2^130 - t_P)"),
            a_prime,
            13,
            false,
        )?;
        let a_prime = zs[0].clone();
        assert_eq!(zs.len(), 14); // [z_0, z_1, ..., z13]

        Ok((a_prime, zs[13].clone()))
    }

    /// Witnesses and decomposes the `b2c'` value we need to check the canonicity of `nk`.
    ///
    /// [Specification](https://p.z.cash/orchard-0.1:commit-ivk-canonicity-nk?partial).
    #[allow(clippy::type_complexity)]
    fn nk_canonicity(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        mut layouter: impl Layouter<pallas::Base>,
        b_2: &RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        c: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            AssignedCell<pallas::Base, pallas::Base>,
            AssignedCell<pallas::Base, pallas::Base>,
        ),
        Error,
    > {
        // `nk` = `b_2 (5 bits) || c (240 bits) || d_0 (9 bits) || d_1 (1 bit)
        // - d_1 = 1 => d_0 = 0
        // - d_1 = 1 => b_2 + c * 2^5 < t_P
        //      - 0 ≤ b_2 + c * 2^5 < 2^140
        //          - b_2 was constrained to be 5 bits.
        //          - z_13 of SinsemillaHash(c) constrains bits 5..=134 to 130 bits
        //          - so b_2 + c * 2^5 is constrained to be 135 bits < 2^140.
        //      - 0 ≤ b_2 + c * 2^5 + 2^140 - t_P < 2^140 (14 ten-bit lookups)

        // Decompose the low 140 bits of b2_c_prime = b_2 + c * 2^5 + 2^140 - t_P, and output
        // the running sum at the end of it. If b2_c_prime < 2^140, the running sum will be 0.
        let b2_c_prime = {
            let two_pow_5 = Value::known(pallas::Base::from(1 << 5));
            let two_pow_140 = Value::known(pallas::Base::from_u128(1u128 << 70).square());
            let t_p = Value::known(pallas::Base::from_u128(T_P));
            b_2.inner().value() + c.value() * two_pow_5 + two_pow_140 - t_p
        };
        let zs = lookup_config.witness_check(
            layouter.namespace(|| "Decompose low 140 bits of (b_2 + c * 2^5 + 2^140 - t_P)"),
            b2_c_prime,
            14,
            false,
        )?;
        let b2_c_prime = zs[0].clone();
        assert_eq!(zs.len(), 15); // [z_0, z_1, ..., z14]

        Ok((b2_c_prime, zs[14].clone()))
    }
}
```

#### NoteCommitChip

最后的NoteCommit芯片也是同样，它是对，在[zcash/orchard/src/circuit/note_commit.rs](https://github.com/zcash/orchard/blob/b448f3f4c5d65fd7bc167df3d4f73f4bb94b7806/src/circuit/note_commit.rs)可以找到，

```rust
impl NoteCommitChip {
    #[allow(non_snake_case)]
    #[allow(clippy::many_single_char_names)]
    pub(in crate::circuit) fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 10],
        sinsemilla_config: SinsemillaConfig<
            OrchardHashDomains,
            OrchardCommitDomains,
            OrchardFixedBases,
        >,
    ) -> NoteCommitConfig {
        // Useful constants
        let two = pallas::Base::from(2);
        let two_pow_2 = pallas::Base::from(1 << 2);
        let two_pow_4 = two_pow_2.square();
        let two_pow_5 = two_pow_4 * two;
        let two_pow_6 = two_pow_5 * two;
        let two_pow_8 = two_pow_4.square();
        let two_pow_9 = two_pow_8 * two;
        let two_pow_10 = two_pow_9 * two;
        let two_pow_58 = pallas::Base::from(1 << 58);
        let two_pow_130 = Expression::Constant(pallas::Base::from_u128(1 << 65).square());
        let two_pow_140 = Expression::Constant(pallas::Base::from_u128(1 << 70).square());
        let two_pow_249 = pallas::Base::from_u128(1 << 124).square() * two;
        let two_pow_250 = two_pow_249 * two;
        let two_pow_254 = pallas::Base::from_u128(1 << 127).square();

        let t_p = Expression::Constant(pallas::Base::from_u128(T_P));

        // Columns used for MessagePiece and message input gates.
        let col_l = advices[6];
        let col_m = advices[7];
        let col_r = advices[8];
        let col_z = advices[9];

        let b = DecomposeB::configure(meta, col_l, col_m, col_r, two_pow_4, two_pow_5, two_pow_6);
        let d = DecomposeD::configure(meta, col_l, col_m, col_r, two, two_pow_2, two_pow_10);
        let e = DecomposeE::configure(meta, col_l, col_m, col_r, two_pow_6);
        let g = DecomposeG::configure(meta, col_l, col_m, two, two_pow_10);
        let h = DecomposeH::configure(meta, col_l, col_m, col_r, two_pow_5);

        let g_d = GdCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_130.clone(),
            two_pow_250,
            two_pow_254,
            t_p.clone(),
        );

        let pk_d = PkdCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_4,
            two_pow_140.clone(),
            two_pow_254,
            t_p.clone(),
        );

        let value =
            ValueCanonicity::configure(meta, col_l, col_m, col_r, col_z, two_pow_8, two_pow_58);

        let rho = RhoCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_4,
            two_pow_140,
            two_pow_254,
            t_p.clone(),
        );

        let psi = PsiCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_9,
            two_pow_130.clone(),
            two_pow_249,
            two_pow_254,
            t_p.clone(),
        );

        let y_canon = YCanonicity::configure(
            meta,
            advices,
            two,
            two_pow_10,
            two_pow_130,
            two_pow_250,
            two_pow_254,
            t_p,
        );

        NoteCommitConfig {
            b,
            d,
            e,
            g,
            h,
            g_d,
            pk_d,
            value,
            rho,
            psi,
            y_canon,
            advices,
            sinsemilla_config,
        }
    }

    pub(in crate::circuit) fn construct(config: NoteCommitConfig) -> Self {
        Self { config }
    }
}
```

可以看到该芯片又间接设置了大量其他的低级芯片，而它的方法也是对其他芯片的组合，比如`SinsemillaChip`、`EccChip`，

```rust
pub(in crate::circuit) mod gadgets {
    use halo2_proofs::circuit::{Chip, Value};

    use super::*;

    #[allow(clippy::many_single_char_names)]
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    pub(in crate::circuit) fn note_commit(
        mut layouter: impl Layouter<pallas::Base>,
        chip: SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
        ecc_chip: EccChip<OrchardFixedBases>,
        note_commit_chip: NoteCommitChip,
        g_d: &NonIdentityEccPoint,
        pk_d: &NonIdentityEccPoint,
        value: AssignedCell<NoteValue, pallas::Base>,
        rho: AssignedCell<pallas::Base, pallas::Base>,
        psi: AssignedCell<pallas::Base, pallas::Base>,
        rcm: ScalarFixed<pallas::Affine, EccChip<OrchardFixedBases>>,
    ) -> Result<Point<pallas::Affine, EccChip<OrchardFixedBases>>, Error> {
        let lookup_config = chip.config().lookup_config();

        // `a` = bits 0..=249 of `x(g_d)`
        let a = MessagePiece::from_subpieces(
            chip.clone(),
            layouter.namespace(|| "a"),
            [RangeConstrained::bitrange_of(g_d.x().value(), 0..250)],
        )?;

        // b = b_0 || b_1 || b_2 || b_3
        //   = (bits 250..=253 of x(g_d)) || (bit 254 of x(g_d)) || (ỹ bit of g_d) || (bits 0..=3 of pk★_d)
        let (b, b_0, b_1, b_2, b_3) =
            DecomposeB::decompose(&lookup_config, chip.clone(), &mut layouter, g_d, pk_d)?;

        // c = bits 4..=253 of pk★_d
        let c = MessagePiece::from_subpieces(
            chip.clone(),
            layouter.namespace(|| "c"),
            [RangeConstrained::bitrange_of(pk_d.x().value(), 4..254)],
        )?;

        // d = d_0 || d_1 || d_2 || d_3
        //   = (bit 254 of x(pk_d)) || (ỹ bit of pk_d) || (bits 0..=7 of v) || (bits 8..=57 of v)
        let (d, d_0, d_1, d_2) =
            DecomposeD::decompose(&lookup_config, chip.clone(), &mut layouter, pk_d, &value)?;

        // e = e_0 || e_1 = (bits 58..=63 of v) || (bits 0..=3 of rho)
        let (e, e_0, e_1) =
            DecomposeE::decompose(&lookup_config, chip.clone(), &mut layouter, &value, &rho)?;

        // f = bits 4..=253 inclusive of rho
        let f = MessagePiece::from_subpieces(
            chip.clone(),
            layouter.namespace(|| "f"),
            [RangeConstrained::bitrange_of(rho.value(), 4..254)],
        )?;

        // g = g_0 || g_1 || g_2
        //   = (bit 254 of rho) || (bits 0..=8 of psi) || (bits 9..=248 of psi)
        let (g, g_0, g_1) =
            DecomposeG::decompose(&lookup_config, chip.clone(), &mut layouter, &rho, &psi)?;

        // h = h_0 || h_1 || h_2
        //   = (bits 249..=253 of psi) || (bit 254 of psi) || 4 zero bits
        let (h, h_0, h_1) =
            DecomposeH::decompose(&lookup_config, chip.clone(), &mut layouter, &psi)?;

        // Check decomposition of `y(g_d)`.
        let b_2 = y_canonicity(
            &lookup_config,
            &note_commit_chip.config.y_canon,
            layouter.namespace(|| "y(g_d) decomposition"),
            g_d.y(),
            b_2,
        )?;
        // Check decomposition of `y(pk_d)`.
        let d_1 = y_canonicity(
            &lookup_config,
            &note_commit_chip.config.y_canon,
            layouter.namespace(|| "y(pk_d) decomposition"),
            pk_d.y(),
            d_1,
        )?;

        // cm = NoteCommit^Orchard_rcm(g★_d || pk★_d || i2lebsp_{64}(v) || rho || psi)
        //
        // `cm = ⊥` is handled internally to `CommitDomain::commit`: incomplete addition
        // constraints allows ⊥ to occur, and then during synthesis it detects these edge
        // cases and raises an error (aborting proof creation).
        //
        // https://p.z.cash/ZKS:action-cm-old-integrity?partial
        // https://p.z.cash/ZKS:action-cmx-new-integrity?partial
        let (cm, zs) = {
            let message = Message::from_pieces(
                chip.clone(),
                vec![
                    a.clone(),
                    b.clone(),
                    c.clone(),
                    d.clone(),
                    e.clone(),
                    f.clone(),
                    g.clone(),
                    h.clone(),
                ],
            );
            let domain = CommitDomain::new(chip, ecc_chip, &OrchardCommitDomains::NoteCommit);
            domain.commit(
                layouter.namespace(|| "Process NoteCommit inputs"),
                message,
                rcm,
            )?
        };

        // `CommitDomain::commit` returns the running sum for each `MessagePiece`. Grab
        // the outputs that we will need for canonicity checks.
        let z13_a = zs[0][13].clone();
        let z13_c = zs[2][13].clone();
        let z1_d = zs[3][1].clone();
        let z13_f = zs[5][13].clone();
        let z1_g = zs[6][1].clone();
        let g_2 = z1_g.clone();
        let z13_g = zs[6][13].clone();

        // Witness and constrain the bounds we need to ensure canonicity.
        let (a_prime, z13_a_prime) = canon_bitshift_130(
            &lookup_config,
            layouter.namespace(|| "x(g_d) canonicity"),
            a.inner().cell_value(),
        )?;

        let (b3_c_prime, z14_b3_c_prime) = pkd_x_canonicity(
            &lookup_config,
            layouter.namespace(|| "x(pk_d) canonicity"),
            b_3.clone(),
            c.inner().cell_value(),
        )?;

        let (e1_f_prime, z14_e1_f_prime) = rho_canonicity(
            &lookup_config,
            layouter.namespace(|| "rho canonicity"),
            e_1.clone(),
            f.inner().cell_value(),
        )?;

        let (g1_g2_prime, z13_g1_g2_prime) = psi_canonicity(
            &lookup_config,
            layouter.namespace(|| "psi canonicity"),
            g_1.clone(),
            g_2,
        )?;

        // Finally, assign values to all of the NoteCommit regions.
        let cfg = note_commit_chip.config;

        let b_1 = cfg
            .b
            .assign(&mut layouter, b, b_0.clone(), b_1, b_2, b_3.clone())?;

        let d_0 = cfg
            .d
            .assign(&mut layouter, d, d_0, d_1, d_2.clone(), z1_d.clone())?;

        cfg.e.assign(&mut layouter, e, e_0.clone(), e_1.clone())?;

        let g_0 = cfg
            .g
            .assign(&mut layouter, g, g_0, g_1.clone(), z1_g.clone())?;

        let h_1 = cfg.h.assign(&mut layouter, h, h_0.clone(), h_1)?;

        cfg.g_d
            .assign(&mut layouter, g_d, a, b_0, b_1, a_prime, z13_a, z13_a_prime)?;

        cfg.pk_d.assign(
            &mut layouter,
            pk_d,
            b_3,
            c,
            d_0,
            b3_c_prime,
            z13_c,
            z14_b3_c_prime,
        )?;

        cfg.value.assign(&mut layouter, value, d_2, z1_d, e_0)?;

        cfg.rho.assign(
            &mut layouter,
            rho,
            e_1,
            f,
            g_0,
            e1_f_prime,
            z13_f,
            z14_e1_f_prime,
        )?;

        cfg.psi.assign(
            &mut layouter,
            psi,
            g_1,
            z1_g,
            h_0,
            h_1,
            g1_g2_prime,
            z13_g,
            z13_g1_g2_prime,
        )?;

        Ok(cm)
    }

    /// A canonicity check helper used in checking x(g_d), y(g_d), and y(pk_d).
    ///
    /// Specifications:
    /// - [`g_d` canonicity](https://p.z.cash/orchard-0.1:note-commit-canonicity-g_d?partial)
    /// - [`y` canonicity](https://p.z.cash/orchard-0.1:note-commit-canonicity-y?partial)
    fn canon_bitshift_130(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        mut layouter: impl Layouter<pallas::Base>,
        a: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<CanonicityBounds, Error> {
        // element = `a (250 bits) || b_0 (4 bits) || b_1 (1 bit)`
        // - b_1 = 1 => b_0 = 0
        // - b_1 = 1 => a < t_P
        //     - 0 ≤ a < 2^130 (z_13 of SinsemillaHash(a))
        //     - 0 ≤ a + 2^130 - t_P < 2^130 (thirteen 10-bit lookups)

        // Decompose the low 130 bits of a_prime = a + 2^130 - t_P, and output
        // the running sum at the end of it. If a_prime < 2^130, the running sum
        // will be 0.
        let a_prime = {
            let two_pow_130 = Value::known(pallas::Base::from_u128(1u128 << 65).square());
            let t_p = Value::known(pallas::Base::from_u128(T_P));
            a.value() + two_pow_130 - t_p
        };
        let zs = lookup_config.witness_check(
            layouter.namespace(|| "Decompose low 130 bits of (a + 2^130 - t_P)"),
            a_prime,
            13,
            false,
        )?;
        let a_prime = zs[0].clone();
        assert_eq!(zs.len(), 14); // [z_0, z_1, ..., z_13]

        Ok((a_prime, zs[13].clone()))
    }

    /// Check canonicity of `x(pk_d)` encoding.
    ///
    /// [Specification](https://p.z.cash/orchard-0.1:note-commit-canonicity-pk_d?partial).
    fn pkd_x_canonicity(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        mut layouter: impl Layouter<pallas::Base>,
        b_3: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        c: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<CanonicityBounds, Error> {
        // `x(pk_d)` = `b_3 (4 bits) || c (250 bits) || d_0 (1 bit)`
        // - d_0 = 1 => b_3 + 2^4 c < t_P
        //     - 0 ≤ b_3 + 2^4 c < 2^134
        //         - b_3 is part of the Sinsemilla message piece
        //           b = b_0 (4 bits) || b_1 (1 bit) || b_2 (1 bit) || b_3 (4 bits)
        //         - b_3 is individually constrained to be 4 bits.
        //         - z_13 of SinsemillaHash(c) == 0 constrains bits 4..=253 of pkd_x
        //           to 130 bits. z13_c is directly checked in the gate.
        //     - 0 ≤ b_3 + 2^4 c + 2^140 - t_P < 2^140 (14 ten-bit lookups)

        // Decompose the low 140 bits of b3_c_prime = b_3 + 2^4 c + 2^140 - t_P,
        // and output the running sum at the end of it.
        // If b3_c_prime < 2^140, the running sum will be 0.
        let b3_c_prime = {
            let two_pow_4 = Value::known(pallas::Base::from(1u64 << 4));
            let two_pow_140 = Value::known(pallas::Base::from_u128(1u128 << 70).square());
            let t_p = Value::known(pallas::Base::from_u128(T_P));
            b_3.inner().value() + (two_pow_4 * c.value()) + two_pow_140 - t_p
        };

        let zs = lookup_config.witness_check(
            layouter.namespace(|| "Decompose low 140 bits of (b_3 + 2^4 c + 2^140 - t_P)"),
            b3_c_prime,
            14,
            false,
        )?;
        let b3_c_prime = zs[0].clone();
        assert_eq!(zs.len(), 15); // [z_0, z_1, ..., z_13, z_14]

        Ok((b3_c_prime, zs[14].clone()))
    }

    /// Check canonicity of `rho` encoding.
    ///
    /// [Specification](https://p.z.cash/orchard-0.1:note-commit-canonicity-rho?partial).
    fn rho_canonicity(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        mut layouter: impl Layouter<pallas::Base>,
        e_1: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        f: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<CanonicityBounds, Error> {
        // `rho` = `e_1 (4 bits) || f (250 bits) || g_0 (1 bit)`
        // - g_0 = 1 => e_1 + 2^4 f < t_P
        // - 0 ≤ e_1 + 2^4 f < 2^134
        //     - e_1 is part of the Sinsemilla message piece
        //       e = e_0 (56 bits) || e_1 (4 bits)
        //     - e_1 is individually constrained to be 4 bits.
        //     - z_13 of SinsemillaHash(f) == 0 constrains bits 4..=253 of rho
        //       to 130 bits. z13_f == 0 is directly checked in the gate.
        // - 0 ≤ e_1 + 2^4 f + 2^140 - t_P < 2^140 (14 ten-bit lookups)

        let e1_f_prime = {
            let two_pow_4 = Value::known(pallas::Base::from(1u64 << 4));
            let two_pow_140 = Value::known(pallas::Base::from_u128(1u128 << 70).square());
            let t_p = Value::known(pallas::Base::from_u128(T_P));
            e_1.inner().value() + (two_pow_4 * f.value()) + two_pow_140 - t_p
        };

        // Decompose the low 140 bits of e1_f_prime = e_1 + 2^4 f + 2^140 - t_P,
        // and output the running sum at the end of it.
        // If e1_f_prime < 2^140, the running sum will be 0.
        let zs = lookup_config.witness_check(
            layouter.namespace(|| "Decompose low 140 bits of (e_1 + 2^4 f + 2^140 - t_P)"),
            e1_f_prime,
            14,
            false,
        )?;
        let e1_f_prime = zs[0].clone();
        assert_eq!(zs.len(), 15); // [z_0, z_1, ..., z_13, z_14]

        Ok((e1_f_prime, zs[14].clone()))
    }

    /// Check canonicity of `psi` encoding.
    ///
    /// [Specification](https://p.z.cash/orchard-0.1:note-commit-canonicity-psi?partial).
    fn psi_canonicity(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        mut layouter: impl Layouter<pallas::Base>,
        g_1: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        g_2: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<CanonicityBounds, Error> {
        // `psi` = `g_1 (9 bits) || g_2 (240 bits) || h_0 (5 bits) || h_1 (1 bit)`
        // - h_1 = 1 => (h_0 = 0) ∧ (g_1 + 2^9 g_2 < t_P)
        // - 0 ≤ g_1 + 2^9 g_2 < 2^130
        //     - g_1 is individually constrained to be 9 bits
        //     - z_13 of SinsemillaHash(g) == 0 constrains bits 0..=248 of psi
        //       to 130 bits. z13_g == 0 is directly checked in the gate.
        // - 0 ≤ g_1 + (2^9)g_2 + 2^130 - t_P < 2^130 (13 ten-bit lookups)

        // Decompose the low 130 bits of g1_g2_prime = g_1 + (2^9)g_2 + 2^130 - t_P,
        // and output the running sum at the end of it.
        // If g1_g2_prime < 2^130, the running sum will be 0.
        let g1_g2_prime = {
            let two_pow_9 = Value::known(pallas::Base::from(1u64 << 9));
            let two_pow_130 = Value::known(pallas::Base::from_u128(1u128 << 65).square());
            let t_p = Value::known(pallas::Base::from_u128(T_P));
            g_1.inner().value() + (two_pow_9 * g_2.value()) + two_pow_130 - t_p
        };

        let zs = lookup_config.witness_check(
            layouter.namespace(|| "Decompose low 130 bits of (g_1 + (2^9)g_2 + 2^130 - t_P)"),
            g1_g2_prime,
            13,
            false,
        )?;
        let g1_g2_prime = zs[0].clone();
        assert_eq!(zs.len(), 14); // [z_0, z_1, ..., z_13]

        Ok((g1_g2_prime, zs[13].clone()))
    }

    /// Check canonicity of y-coordinate given its LSB as a value.
    /// Also, witness the LSB and return the witnessed cell.
    ///
    /// Specifications:
    /// - [`y` decomposition](https://p.z.cash/orchard-0.1:note-commit-decomposition-y?partial)
    /// - [`y` canonicity](https://p.z.cash/orchard-0.1:note-commit-canonicity-y?partial)
    fn y_canonicity(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        y_canon: &YCanonicity,
        mut layouter: impl Layouter<pallas::Base>,
        y: AssignedCell<pallas::Base, pallas::Base>,
        lsb: RangeConstrained<pallas::Base, Value<pallas::Base>>,
    ) -> Result<RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>, Error>
    {
        // Decompose the field element
        //      y = LSB || k_0 || k_1 || k_2 || k_3
        //        = (bit 0) || (bits 1..=9) || (bits 10..=249) || (bits 250..=253) || (bit 254)

        // Range-constrain k_0 to be 9 bits.
        let k_0 = RangeConstrained::witness_short(
            lookup_config,
            layouter.namespace(|| "k_0"),
            y.value(),
            1..10,
        )?;

        // k_1 will be constrained by the decomposition of j.
        let k_1 = RangeConstrained::bitrange_of(y.value(), 10..250);

        // Range-constrain k_2 to be 4 bits.
        let k_2 = RangeConstrained::witness_short(
            lookup_config,
            layouter.namespace(|| "k_2"),
            y.value(),
            250..254,
        )?;

        // k_3 will be boolean-constrained in the gate.
        let k_3 = RangeConstrained::bitrange_of(y.value(), 254..255);

        // Decompose j = LSB + (2)k_0 + (2^10)k_1 using 25 ten-bit lookups.
        let (j, z1_j, z13_j) = {
            let j = {
                let two = Value::known(pallas::Base::from(2));
                let two_pow_10 = Value::known(pallas::Base::from(1 << 10));
                lsb.inner().value() + two * k_0.inner().value() + two_pow_10 * k_1.inner().value()
            };
            let zs = lookup_config.witness_check(
                layouter.namespace(|| "Decompose j = LSB + (2)k_0 + (2^10)k_1"),
                j,
                25,
                true,
            )?;
            (zs[0].clone(), zs[1].clone(), zs[13].clone())
        };

        // Decompose j_prime = j + 2^130 - t_P using 13 ten-bit lookups.
        // We can reuse the canon_bitshift_130 logic here.
        let (j_prime, z13_j_prime) = canon_bitshift_130(
            lookup_config,
            layouter.namespace(|| "j_prime = j + 2^130 - t_P"),
            j.clone(),
        )?;

        y_canon.assign(
            &mut layouter,
            y,
            lsb,
            k_0,
            k_2,
            k_3,
            j,
            z1_j,
            z13_j,
            j_prime,
            z13_j_prime,
        )
    }
}
```

#### Gadgets

以上芯片已经描述了大部分Orchard中所需的电路计算，下面再介绍一些电路上的关键过程，首先是value commitment的计算，位于[zcash/orchard/src/circuit/gadget.rs](https://github.com/zcash/orchard/blob/be69324b9cab8179a61b2b8ee2a51a146665cd8d/src/circuit/gadget.rs)，

```rust
/// `ValueCommit^Orchard` from [Section 5.4.8.3 Homomorphic Pedersen commitments (Sapling and Orchard)].
///
/// [Section 5.4.8.3 Homomorphic Pedersen commitments (Sapling and Orchard)]: https://zips.z.cash/protocol/protocol.pdf#concretehomomorphiccommit
pub(in crate::circuit) fn value_commit_orchard<
    EccChip: EccInstructions<
        pallas::Affine,
        FixedPoints = OrchardFixedBases,
        Var = AssignedCell<pallas::Base, pallas::Base>,
    >,
>(
    mut layouter: impl Layouter<pallas::Base>,
    ecc_chip: EccChip,
    v: ScalarFixedShort<pallas::Affine, EccChip>,
    rcv: ScalarFixed<pallas::Affine, EccChip>,
) -> Result<Point<pallas::Affine, EccChip>, plonk::Error> {
    // commitment = [v] ValueCommitV
    let (commitment, _) = {
        let value_commit_v = ValueCommitV;
        let value_commit_v = FixedPointShort::from_inner(ecc_chip.clone(), value_commit_v);
        value_commit_v.mul(layouter.namespace(|| "[v] ValueCommitV"), v)?
    };

    // blind = [rcv] ValueCommitR
    let (blind, _rcv) = {
        let value_commit_r = OrchardFixedBasesFull::ValueCommitR;
        let value_commit_r = FixedPoint::from_inner(ecc_chip, value_commit_r);

        // [rcv] ValueCommitR
        value_commit_r.mul(layouter.namespace(|| "[rcv] ValueCommitR"), rcv)?
    };

    // [v] ValueCommitV + [rcv] ValueCommitR
    commitment.add(layouter.namespace(|| "cv"), &blind)
}
```

然后是nullifier的计算，在同样的位置，

```rust
/// `DeriveNullifier` from [Section 4.16: Note Commitments and Nullifiers].
///
/// [Section 4.16: Note Commitments and Nullifiers]: https://zips.z.cash/protocol/protocol.pdf#commitmentsandnullifiers
#[allow(clippy::too_many_arguments)]
pub(in crate::circuit) fn derive_nullifier<
    PoseidonChip: PoseidonSpongeInstructions<pallas::Base, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>,
    AddChip: AddInstruction<pallas::Base>,
    EccChip: EccInstructions<
        pallas::Affine,
        FixedPoints = OrchardFixedBases,
        Var = AssignedCell<pallas::Base, pallas::Base>,
    >,
>(
    mut layouter: impl Layouter<pallas::Base>,
    poseidon_chip: PoseidonChip,
    add_chip: AddChip,
    ecc_chip: EccChip,
    rho: AssignedCell<pallas::Base, pallas::Base>,
    psi: &AssignedCell<pallas::Base, pallas::Base>,
    cm: &Point<pallas::Affine, EccChip>,
    nk: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<X<pallas::Affine, EccChip>, plonk::Error> {
    // hash = poseidon_hash(nk, rho)
    let hash = {
        let poseidon_message = [nk, rho];
        let poseidon_hasher =
            PoseidonHash::init(poseidon_chip, layouter.namespace(|| "Poseidon init"))?;
        poseidon_hasher.hash(
            layouter.namespace(|| "Poseidon hash (nk, rho)"),
            poseidon_message,
        )?
    };

    // Add hash output to psi.
    // `scalar` = poseidon_hash(nk, rho) + psi.
    let scalar = add_chip.add(
        layouter.namespace(|| "scalar = poseidon_hash(nk, rho) + psi"),
        &hash,
        psi,
    )?;

    // Multiply scalar by NullifierK
    // `product` = [poseidon_hash(nk, rho) + psi] NullifierK.
    //
    let product = {
        let nullifier_k = FixedPointBaseField::from_inner(ecc_chip, NullifierK);
        nullifier_k.mul(
            layouter.namespace(|| "[poseidon_output + psi] NullifierK"),
            scalar,
        )?
    };

    // Add cm to multiplied fixed base to get nf
    // cm + [poseidon_output + psi] NullifierK
    cm.add(layouter.namespace(|| "nf"), &product)
        .map(|res| res.extract_p())
}
```

### 证明生成

接下来我们可以在[zcash/orchard/src/circuit.rs](https://github.com/zcash/orchard/blob/5fbbded49e3162a31fd3bb0de3c344f3cc4dfa60/src/circuit.rs)找到证明的定义，

```rust
pub struct Instance {
    pub(crate) anchor: Anchor,
    pub(crate) cv_net: ValueCommitment,
    pub(crate) nf_old: Nullifier,
    pub(crate) rk: VerificationKey<SpendAuth>,
    pub(crate) cmx: ExtractedNoteCommitment,
    pub(crate) enable_spend: bool,
    pub(crate) enable_output: bool,
}

impl Proof {
    /// Creates a proof for the given circuits and instances.
    pub fn create(
        pk: &ProvingKey,
        circuits: &[Circuit],
        instances: &[Instance],
        mut rng: impl RngCore,
    ) -> Result<Self, plonk::Error> {
        let instances: Vec<_> = instances.iter().map(|i| i.to_halo2_instance()).collect();
        let instances: Vec<Vec<_>> = instances
            .iter()
            .map(|i| i.iter().map(|c| &c[..]).collect())
            .collect();
        let instances: Vec<_> = instances.iter().map(|i| &i[..]).collect();

        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        plonk::create_proof(
            &pk.params,
            &pk.pk,
            circuits,
            &instances,
            &mut rng,
            &mut transcript,
        )?;
        Ok(Proof(transcript.finalize()))
    }

    /// Verifies this proof with the given instances.
    pub fn verify(&self, vk: &VerifyingKey, instances: &[Instance]) -> Result<(), plonk::Error> {
        let instances: Vec<_> = instances.iter().map(|i| i.to_halo2_instance()).collect();
        let instances: Vec<Vec<_>> = instances
            .iter()
            .map(|i| i.iter().map(|c| &c[..]).collect())
            .collect();
        let instances: Vec<_> = instances.iter().map(|i| &i[..]).collect();

        let strategy = SingleVerifier::new(&vk.params);
        let mut transcript = Blake2bRead::init(&self.0[..]);
        plonk::verify_proof(&vk.params, &vk.vk, strategy, &instances, &mut transcript)
    }

    /// Adds this proof to the given batch for verification with the given instances.
    ///
    /// Use this API if you want more control over how proof batches are processed. If you
    /// just want to batch-validate Orchard bundles, use [`bundle::BatchValidator`].
    ///
    /// [`bundle::BatchValidator`]: crate::bundle::BatchValidator
    pub fn add_to_batch(&self, batch: &mut BatchVerifier<vesta::Affine>, instances: Vec<Instance>) {
        let instances = instances
            .iter()
            .map(|i| {
                i.to_halo2_instance()
                    .into_iter()
                    .map(|c| c.into_iter().collect())
                    .collect()
            })
            .collect();

        batch.add_proof(instances, self.0.clone());
    }

    /// Constructs a new Proof value.
    pub fn new(bytes: Vec<u8>) -> Self {
        Proof(bytes)
    }
}
```

可以看到每个`Instance`对应一对可能的销毁和铸造，而`Proof::create`接收一个`Instance`的数组和一个对应的`Circuit`数组。方法最后调用到`plonk`，我们可以在[zcash/halo2/halo2_proofs/src/plonk/prover.rs](https://github.com/zcash/halo2/blob/41c87eac0f9766dc36af94291ae8537581b1272b/halo2_proofs/src/plonk/prover.rs)找到，

```rust
/// This creates a proof for the provided `circuit` when given the public
/// parameters `params` and the proving key [`ProvingKey`] that was
/// generated previously for the same circuit. The provided `instances`
/// are zero-padded internally.
pub fn create_proof<
    C: CurveAffine,
    E: EncodedChallenge<C>,
    R: RngCore,
    T: TranscriptWrite<C, E>,
    ConcreteCircuit: Circuit<C::Scalar>,
>(
    params: &Params<C>,
    pk: &ProvingKey<C>,
    circuits: &[ConcreteCircuit],
    instances: &[&[&[C::Scalar]]],
    mut rng: R,
    transcript: &mut T,
) -> Result<(), Error> {
    if circuits.len() != instances.len() {
        return Err(Error::InvalidInstances);
    }

    for instance in instances.iter() {
        if instance.len() != pk.vk.cs.num_instance_columns {
            return Err(Error::InvalidInstances);
        }
    }

    // Hash verification key into transcript
    pk.vk.hash_into(transcript)?;

    let domain = &pk.vk.domain;
    let mut meta = ConstraintSystem::default();
    let config = ConcreteCircuit::configure(&mut meta);

    // Selector optimizations cannot be applied here; use the ConstraintSystem
    // from the verification key.
    let meta = &pk.vk.cs;

    struct InstanceSingle<C: CurveAffine> {
        pub instance_values: Vec<Polynomial<C::Scalar, LagrangeCoeff>>,
        pub instance_polys: Vec<Polynomial<C::Scalar, Coeff>>,
        pub instance_cosets: Vec<Polynomial<C::Scalar, ExtendedLagrangeCoeff>>,
    }

    let instance: Vec<InstanceSingle<C>> = instances
        .iter()
        .map(|instance| -> Result<InstanceSingle<C>, Error> {
            let instance_values = instance
                .iter()
                .map(|values| {
                    let mut poly = domain.empty_lagrange();
                    assert_eq!(poly.len(), params.n as usize);
                    if values.len() > (poly.len() - (meta.blinding_factors() + 1)) {
                        return Err(Error::InstanceTooLarge);
                    }
                    for (poly, value) in poly.iter_mut().zip(values.iter()) {
                        *poly = *value;
                    }
                    Ok(poly)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let instance_commitments_projective: Vec<_> = instance_values
                .iter()
                .map(|poly| params.commit_lagrange(poly, Blind::default()))
                .collect();
            let mut instance_commitments =
                vec![C::identity(); instance_commitments_projective.len()];
            C::Curve::batch_normalize(&instance_commitments_projective, &mut instance_commitments);
            let instance_commitments = instance_commitments;
            drop(instance_commitments_projective);

            for commitment in &instance_commitments {
                transcript.common_point(*commitment)?;
            }

            let instance_polys: Vec<_> = instance_values
                .iter()
                .map(|poly| {
                    let lagrange_vec = domain.lagrange_from_vec(poly.to_vec());
                    domain.lagrange_to_coeff(lagrange_vec)
                })
                .collect();

            let instance_cosets: Vec<_> = instance_polys
                .iter()
                .map(|poly| domain.coeff_to_extended(poly.clone()))
                .collect();

            Ok(InstanceSingle {
                instance_values,
                instance_polys,
                instance_cosets,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    struct AdviceSingle<C: CurveAffine> {
        pub advice_values: Vec<Polynomial<C::Scalar, LagrangeCoeff>>,
        pub advice_polys: Vec<Polynomial<C::Scalar, Coeff>>,
        pub advice_cosets: Vec<Polynomial<C::Scalar, ExtendedLagrangeCoeff>>,
        pub advice_blinds: Vec<Blind<C::Scalar>>,
    }

    let advice: Vec<AdviceSingle<C>> = circuits
        .iter()
        .zip(instances.iter())
        .map(|(circuit, instances)| -> Result<AdviceSingle<C>, Error> {
            struct WitnessCollection<'a, F: Field> {
                k: u32,
                pub advice: Vec<Polynomial<Assigned<F>, LagrangeCoeff>>,
                instances: &'a [&'a [F]],
                usable_rows: RangeTo<usize>,
                _marker: std::marker::PhantomData<F>,
            }

            impl<'a, F: Field> Assignment<F> for WitnessCollection<'a, F> {
                fn enter_region<NR, N>(&mut self, _: N)
                where
                    NR: Into<String>,
                    N: FnOnce() -> NR,
                {
                    // Do nothing; we don't care about regions in this context.
                }

                fn exit_region(&mut self) {
                    // Do nothing; we don't care about regions in this context.
                }

                fn enable_selector<A, AR>(
                    &mut self,
                    _: A,
                    _: &Selector,
                    _: usize,
                ) -> Result<(), Error>
                where
                    A: FnOnce() -> AR,
                    AR: Into<String>,
                {
                    // We only care about advice columns here

                    Ok(())
                }

                fn query_instance(
                    &self,
                    column: Column<Instance>,
                    row: usize,
                ) -> Result<Value<F>, Error> {
                    if !self.usable_rows.contains(&row) {
                        return Err(Error::not_enough_rows_available(self.k));
                    }

                    self.instances
                        .get(column.index())
                        .and_then(|column| column.get(row))
                        .map(|v| Value::known(*v))
                        .ok_or(Error::BoundsFailure)
                }

                fn assign_advice<V, VR, A, AR>(
                    &mut self,
                    _: A,
                    column: Column<Advice>,
                    row: usize,
                    to: V,
                ) -> Result<(), Error>
                where
                    V: FnOnce() -> Value<VR>,
                    VR: Into<Assigned<F>>,
                    A: FnOnce() -> AR,
                    AR: Into<String>,
                {
                    if !self.usable_rows.contains(&row) {
                        return Err(Error::not_enough_rows_available(self.k));
                    }

                    *self
                        .advice
                        .get_mut(column.index())
                        .and_then(|v| v.get_mut(row))
                        .ok_or(Error::BoundsFailure)? = to().into_field().assign()?;

                    Ok(())
                }

                fn assign_fixed<V, VR, A, AR>(
                    &mut self,
                    _: A,
                    _: Column<Fixed>,
                    _: usize,
                    _: V,
                ) -> Result<(), Error>
                where
                    V: FnOnce() -> Value<VR>,
                    VR: Into<Assigned<F>>,
                    A: FnOnce() -> AR,
                    AR: Into<String>,
                {
                    // We only care about advice columns here

                    Ok(())
                }

                fn copy(
                    &mut self,
                    _: Column<Any>,
                    _: usize,
                    _: Column<Any>,
                    _: usize,
                ) -> Result<(), Error> {
                    // We only care about advice columns here

                    Ok(())
                }

                fn fill_from_row(
                    &mut self,
                    _: Column<Fixed>,
                    _: usize,
                    _: Value<Assigned<F>>,
                ) -> Result<(), Error> {
                    Ok(())
                }

                fn push_namespace<NR, N>(&mut self, _: N)
                where
                    NR: Into<String>,
                    N: FnOnce() -> NR,
                {
                    // Do nothing; we don't care about namespaces in this context.
                }

                fn pop_namespace(&mut self, _: Option<String>) {
                    // Do nothing; we don't care about namespaces in this context.
                }
            }

            let unusable_rows_start = params.n as usize - (meta.blinding_factors() + 1);

            let mut witness = WitnessCollection {
                k: params.k,
                advice: vec![domain.empty_lagrange_assigned(); meta.num_advice_columns],
                instances,
                // The prover will not be allowed to assign values to advice
                // cells that exist within inactive rows, which include some
                // number of blinding factors and an extra row for use in the
                // permutation argument.
                usable_rows: ..unusable_rows_start,
                _marker: std::marker::PhantomData,
            };

            // Synthesize the circuit to obtain the witness and other information.
            ConcreteCircuit::FloorPlanner::synthesize(
                &mut witness,
                circuit,
                config.clone(),
                meta.constants.clone(),
            )?;

            let mut advice = batch_invert_assigned(witness.advice);

            // Add blinding factors to advice columns
            for advice in &mut advice {
                for cell in &mut advice[unusable_rows_start..] {
                    *cell = C::Scalar::random(&mut rng);
                }
            }

            // Compute commitments to advice column polynomials
            let advice_blinds: Vec<_> = advice
                .iter()
                .map(|_| Blind(C::Scalar::random(&mut rng)))
                .collect();
            let advice_commitments_projective: Vec<_> = advice
                .iter()
                .zip(advice_blinds.iter())
                .map(|(poly, blind)| params.commit_lagrange(poly, *blind))
                .collect();
            let mut advice_commitments = vec![C::identity(); advice_commitments_projective.len()];
            C::Curve::batch_normalize(&advice_commitments_projective, &mut advice_commitments);
            let advice_commitments = advice_commitments;
            drop(advice_commitments_projective);

            for commitment in &advice_commitments {
                transcript.write_point(*commitment)?;
            }

            let advice_polys: Vec<_> = advice
                .clone()
                .into_iter()
                .map(|poly| domain.lagrange_to_coeff(poly))
                .collect();

            let advice_cosets: Vec<_> = advice_polys
                .iter()
                .map(|poly| domain.coeff_to_extended(poly.clone()))
                .collect();

            Ok(AdviceSingle {
                advice_values: advice,
                advice_polys,
                advice_cosets,
                advice_blinds,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Create polynomial evaluator context for values.
    let mut value_evaluator = poly::new_evaluator(|| {});

    // Register fixed values with the polynomial evaluator.
    let fixed_values: Vec<_> = pk
        .fixed_values
        .iter()
        .map(|poly| value_evaluator.register_poly(poly.clone()))
        .collect();

    // Register advice values with the polynomial evaluator.
    let advice_values: Vec<_> = advice
        .iter()
        .map(|advice| {
            advice
                .advice_values
                .iter()
                .map(|poly| value_evaluator.register_poly(poly.clone()))
                .collect::<Vec<_>>()
        })
        .collect();

    // Register instance values with the polynomial evaluator.
    let instance_values: Vec<_> = instance
        .iter()
        .map(|instance| {
            instance
                .instance_values
                .iter()
                .map(|poly| value_evaluator.register_poly(poly.clone()))
                .collect::<Vec<_>>()
        })
        .collect();

    // Create polynomial evaluator context for cosets.
    let mut coset_evaluator = poly::new_evaluator(|| {});

    // Register fixed cosets with the polynomial evaluator.
    let fixed_cosets: Vec<_> = pk
        .fixed_cosets
        .iter()
        .map(|poly| coset_evaluator.register_poly(poly.clone()))
        .collect();

    // Register advice cosets with the polynomial evaluator.
    let advice_cosets: Vec<_> = advice
        .iter()
        .map(|advice| {
            advice
                .advice_cosets
                .iter()
                .map(|poly| coset_evaluator.register_poly(poly.clone()))
                .collect::<Vec<_>>()
        })
        .collect();

    // Register instance cosets with the polynomial evaluator.
    let instance_cosets: Vec<_> = instance
        .iter()
        .map(|instance| {
            instance
                .instance_cosets
                .iter()
                .map(|poly| coset_evaluator.register_poly(poly.clone()))
                .collect::<Vec<_>>()
        })
        .collect();

    // Register permutation cosets with the polynomial evaluator.
    let permutation_cosets: Vec<_> = pk
        .permutation
        .cosets
        .iter()
        .map(|poly| coset_evaluator.register_poly(poly.clone()))
        .collect();

    // Register boundary polynomials used in the lookup and permutation arguments.
    let l0 = coset_evaluator.register_poly(pk.l0.clone());
    let l_blind = coset_evaluator.register_poly(pk.l_blind.clone());
    let l_last = coset_evaluator.register_poly(pk.l_last.clone());

    // Sample theta challenge for keeping lookup columns linearly independent
    let theta: ChallengeTheta<_> = transcript.squeeze_challenge_scalar();

    let lookups: Vec<Vec<lookup::prover::Permuted<C, _>>> = instance_values
        .iter()
        .zip(instance_cosets.iter())
        .zip(advice_values.iter())
        .zip(advice_cosets.iter())
        .map(|(((instance_values, instance_cosets), advice_values), advice_cosets)| -> Result<Vec<_>, Error> {
            // Construct and commit to permuted values for each lookup
            pk.vk
                .cs
                .lookups
                .iter()
                .map(|lookup| {
                    lookup.commit_permuted(
                        pk,
                        params,
                        domain,
                        &value_evaluator,
                        &mut coset_evaluator,
                        theta,
                        advice_values,
                        &fixed_values,
                        instance_values,
                        advice_cosets,
                        &fixed_cosets,
                        instance_cosets,
                        &mut rng,
                        transcript,
                    )
                })
                .collect()
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Sample beta challenge
    let beta: ChallengeBeta<_> = transcript.squeeze_challenge_scalar();

    // Sample gamma challenge
    let gamma: ChallengeGamma<_> = transcript.squeeze_challenge_scalar();

    // Commit to permutations.
    let permutations: Vec<permutation::prover::Committed<C, _>> = instance
        .iter()
        .zip(advice.iter())
        .map(|(instance, advice)| {
            pk.vk.cs.permutation.commit(
                params,
                pk,
                &pk.permutation,
                &advice.advice_values,
                &pk.fixed_values,
                &instance.instance_values,
                beta,
                gamma,
                &mut coset_evaluator,
                &mut rng,
                transcript,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let lookups: Vec<Vec<lookup::prover::Committed<C, _>>> = lookups
        .into_iter()
        .map(|lookups| -> Result<Vec<_>, _> {
            // Construct and commit to products for each lookup
            lookups
                .into_iter()
                .map(|lookup| {
                    lookup.commit_product(
                        pk,
                        params,
                        beta,
                        gamma,
                        &mut coset_evaluator,
                        &mut rng,
                        transcript,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Commit to the vanishing argument's random polynomial for blinding h(x_3)
    let vanishing = vanishing::Argument::commit(params, domain, &mut rng, transcript)?;

    // Obtain challenge for keeping all separate gates linearly independent
    let y: ChallengeY<_> = transcript.squeeze_challenge_scalar();

    // Evaluate the h(X) polynomial's constraint system expressions for the permutation constraints.
    let (permutations, permutation_expressions): (Vec<_>, Vec<_>) = permutations
        .into_iter()
        .zip(advice_cosets.iter())
        .zip(instance_cosets.iter())
        .map(|((permutation, advice), instance)| {
            permutation.construct(
                pk,
                &pk.vk.cs.permutation,
                advice,
                &fixed_cosets,
                instance,
                &permutation_cosets,
                l0,
                l_blind,
                l_last,
                beta,
                gamma,
            )
        })
        .unzip();

    let (lookups, lookup_expressions): (Vec<Vec<_>>, Vec<Vec<_>>) = lookups
        .into_iter()
        .map(|lookups| {
            // Evaluate the h(X) polynomial's constraint system expressions for the lookup constraints, if any.
            lookups
                .into_iter()
                .map(|p| p.construct(beta, gamma, l0, l_blind, l_last))
                .unzip()
        })
        .unzip();

    let expressions = advice_cosets
        .iter()
        .zip(instance_cosets.iter())
        .zip(permutation_expressions.into_iter())
        .zip(lookup_expressions.into_iter())
        .flat_map(
            |(((advice_cosets, instance_cosets), permutation_expressions), lookup_expressions)| {
                let fixed_cosets = &fixed_cosets;
                iter::empty()
                    // Custom constraints
                    .chain(meta.gates.iter().flat_map(move |gate| {
                        gate.polynomials().iter().map(move |expr| {
                            expr.evaluate(
                                &poly::Ast::ConstantTerm,
                                &|_| panic!("virtual selectors are removed during optimization"),
                                &|query| {
                                    fixed_cosets[query.column_index]
                                        .with_rotation(query.rotation)
                                        .into()
                                },
                                &|query| {
                                    advice_cosets[query.column_index]
                                        .with_rotation(query.rotation)
                                        .into()
                                },
                                &|query| {
                                    instance_cosets[query.column_index]
                                        .with_rotation(query.rotation)
                                        .into()
                                },
                                &|a| -a,
                                &|a, b| a + b,
                                &|a, b| a * b,
                                &|a, scalar| a * scalar,
                            )
                        })
                    }))
                    // Permutation constraints, if any.
                    .chain(permutation_expressions.into_iter())
                    // Lookup constraints, if any.
                    .chain(lookup_expressions.into_iter().flatten())
            },
        );

    // Construct the vanishing argument's h(X) commitments
    let vanishing = vanishing.construct(
        params,
        domain,
        coset_evaluator,
        expressions,
        y,
        &mut rng,
        transcript,
    )?;

    let x: ChallengeX<_> = transcript.squeeze_challenge_scalar();
    let xn = x.pow(&[params.n, 0, 0, 0]);

    // Compute and hash instance evals for each circuit instance
    for instance in instance.iter() {
        // Evaluate polynomials at omega^i x
        let instance_evals: Vec<_> = meta
            .instance_queries
            .iter()
            .map(|&(column, at)| {
                eval_polynomial(
                    &instance.instance_polys[column.index()],
                    domain.rotate_omega(*x, at),
                )
            })
            .collect();

        // Hash each instance column evaluation
        for eval in instance_evals.iter() {
            transcript.write_scalar(*eval)?;
        }
    }

    // Compute and hash advice evals for each circuit instance
    for advice in advice.iter() {
        // Evaluate polynomials at omega^i x
        let advice_evals: Vec<_> = meta
            .advice_queries
            .iter()
            .map(|&(column, at)| {
                eval_polynomial(
                    &advice.advice_polys[column.index()],
                    domain.rotate_omega(*x, at),
                )
            })
            .collect();

        // Hash each advice column evaluation
        for eval in advice_evals.iter() {
            transcript.write_scalar(*eval)?;
        }
    }

    // Compute and hash fixed evals (shared across all circuit instances)
    let fixed_evals: Vec<_> = meta
        .fixed_queries
        .iter()
        .map(|&(column, at)| {
            eval_polynomial(&pk.fixed_polys[column.index()], domain.rotate_omega(*x, at))
        })
        .collect();

    // Hash each fixed column evaluation
    for eval in fixed_evals.iter() {
        transcript.write_scalar(*eval)?;
    }

    let vanishing = vanishing.evaluate(x, xn, domain, transcript)?;

    // Evaluate common permutation data
    pk.permutation.evaluate(x, transcript)?;

    // Evaluate the permutations, if any, at omega^i x.
    let permutations: Vec<permutation::prover::Evaluated<C>> = permutations
        .into_iter()
        .map(|permutation| -> Result<_, _> { permutation.evaluate(pk, x, transcript) })
        .collect::<Result<Vec<_>, _>>()?;

    // Evaluate the lookups, if any, at omega^i x.
    let lookups: Vec<Vec<lookup::prover::Evaluated<C>>> = lookups
        .into_iter()
        .map(|lookups| -> Result<Vec<_>, _> {
            lookups
                .into_iter()
                .map(|p| p.evaluate(pk, x, transcript))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    let instances = instance
        .iter()
        .zip(advice.iter())
        .zip(permutations.iter())
        .zip(lookups.iter())
        .flat_map(|(((instance, advice), permutation), lookups)| {
            iter::empty()
                .chain(
                    pk.vk
                        .cs
                        .instance_queries
                        .iter()
                        .map(move |&(column, at)| ProverQuery {
                            point: domain.rotate_omega(*x, at),
                            poly: &instance.instance_polys[column.index()],
                            blind: Blind::default(),
                        }),
                )
                .chain(
                    pk.vk
                        .cs
                        .advice_queries
                        .iter()
                        .map(move |&(column, at)| ProverQuery {
                            point: domain.rotate_omega(*x, at),
                            poly: &advice.advice_polys[column.index()],
                            blind: advice.advice_blinds[column.index()],
                        }),
                )
                .chain(permutation.open(pk, x))
                .chain(lookups.iter().flat_map(move |p| p.open(pk, x)).into_iter())
        })
        .chain(
            pk.vk
                .cs
                .fixed_queries
                .iter()
                .map(|&(column, at)| ProverQuery {
                    point: domain.rotate_omega(*x, at),
                    poly: &pk.fixed_polys[column.index()],
                    blind: Blind::default(),
                }),
        )
        .chain(pk.permutation.open(x))
        // We query the h(X) polynomial at x
        .chain(vanishing.open(x));

    multiopen::create_proof(params, rng, transcript, instances).map_err(|_| Error::Opening)
}
```

向下继续调用到[zcash/halo2/halo2_proofs/src/poly/multiopen/prover.rs](https://github.com/zcash/halo2/blob/41c87eac0f9766dc36af94291ae8537581b1272b/halo2_proofs/src/poly/multiopen/prover.rs)，

```rust
/// Create a multi-opening proof
pub fn create_proof<
    'a,
    I,
    C: CurveAffine,
    E: EncodedChallenge<C>,
    R: RngCore,
    T: TranscriptWrite<C, E>,
>(
    params: &Params<C>,
    mut rng: R,
    transcript: &mut T,
    queries: I,
) -> io::Result<()>
where
    I: IntoIterator<Item = ProverQuery<'a, C>> + Clone,
{
    let x_1: ChallengeX1<_> = transcript.squeeze_challenge_scalar();
    let x_2: ChallengeX2<_> = transcript.squeeze_challenge_scalar();

    let (poly_map, point_sets) = construct_intermediate_sets(queries);

    // Collapse openings at same point sets together into single openings using
    // x_1 challenge.
    let mut q_polys: Vec<Option<Polynomial<C::Scalar, Coeff>>> = vec![None; point_sets.len()];
    let mut q_blinds = vec![Blind(C::Scalar::ZERO); point_sets.len()];

    {
        let mut accumulate =
            |set_idx: usize, new_poly: &Polynomial<C::Scalar, Coeff>, blind: Blind<C::Scalar>| {
                if let Some(poly) = &q_polys[set_idx] {
                    q_polys[set_idx] = Some(poly.clone() * *x_1 + new_poly);
                } else {
                    q_polys[set_idx] = Some(new_poly.clone());
                }
                q_blinds[set_idx] *= *x_1;
                q_blinds[set_idx] += blind;
            };

        for commitment_data in poly_map.into_iter() {
            accumulate(
                commitment_data.set_index,        // set_idx,
                commitment_data.commitment.poly,  // poly,
                commitment_data.commitment.blind, // blind,
            );
        }
    }

    let q_prime_poly = point_sets
        .iter()
        .zip(q_polys.iter())
        .fold(None, |q_prime_poly, (points, poly)| {
            let mut poly = points
                .iter()
                .fold(poly.clone().unwrap().values, |poly, point| {
                    kate_division(&poly, *point)
                });
            poly.resize(params.n as usize, C::Scalar::ZERO);
            let poly = Polynomial {
                values: poly,
                _marker: PhantomData,
            };

            if q_prime_poly.is_none() {
                Some(poly)
            } else {
                q_prime_poly.map(|q_prime_poly| q_prime_poly * *x_2 + &poly)
            }
        })
        .unwrap();

    let q_prime_blind = Blind(C::Scalar::random(&mut rng));
    let q_prime_commitment = params.commit(&q_prime_poly, q_prime_blind).to_affine();

    transcript.write_point(q_prime_commitment)?;

    let x_3: ChallengeX3<_> = transcript.squeeze_challenge_scalar();

    // Prover sends u_i for all i, which correspond to the evaluation
    // of each Q polynomial commitment at x_3.
    for q_i_poly in &q_polys {
        transcript.write_scalar(eval_polynomial(q_i_poly.as_ref().unwrap(), *x_3))?;
    }

    let x_4: ChallengeX4<_> = transcript.squeeze_challenge_scalar();

    let (p_poly, p_poly_blind) = q_polys.into_iter().zip(q_blinds.into_iter()).fold(
        (q_prime_poly, q_prime_blind),
        |(q_prime_poly, q_prime_blind), (poly, blind)| {
            (
                q_prime_poly * *x_4 + &poly.unwrap(),
                Blind((q_prime_blind.0 * &(*x_4)) + &blind.0),
            )
        },
    );

    commitment::create_proof(params, rng, transcript, &p_poly, p_poly_blind, *x_3)
}
```

再调用到[zcash/halo2/halo2_proofs/src/poly/commitment/prover.rs](https://github.com/zcash/halo2/blob/41c87eac0f9766dc36af94291ae8537581b1272b/halo2_proofs/src/poly/commitment/prover.rs)，

```rust
/// Create a polynomial commitment opening proof for the polynomial defined
/// by the coefficients `px`, the blinding factor `blind` used for the
/// polynomial commitment, and the point `x` that the polynomial is
/// evaluated at.
///
/// This function will panic if the provided polynomial is too large with
/// respect to the polynomial commitment parameters.
///
/// **Important:** This function assumes that the provided `transcript` has
/// already seen the common inputs: the polynomial commitment P, the claimed
/// opening v, and the point x. It's probably also nice for the transcript
/// to have seen the elliptic curve description and the URS, if you want to
/// be rigorous.
pub fn create_proof<
    C: CurveAffine,
    E: EncodedChallenge<C>,
    R: RngCore,
    T: TranscriptWrite<C, E>,
>(
    params: &Params<C>,
    mut rng: R,
    transcript: &mut T,
    p_poly: &Polynomial<C::Scalar, Coeff>,
    p_blind: Blind<C::Scalar>,
    x_3: C::Scalar,
) -> io::Result<()> {
    // We're limited to polynomials of degree n - 1.
    assert_eq!(p_poly.len(), params.n as usize);

    // Sample a random polynomial (of same degree) that has a root at x_3, first
    // by setting all coefficients to random values.
    let mut s_poly = (*p_poly).clone();
    for coeff in s_poly.iter_mut() {
        *coeff = C::Scalar::random(&mut rng);
    }
    // Evaluate the random polynomial at x_3
    let s_at_x3 = eval_polynomial(&s_poly[..], x_3);
    // Subtract constant coefficient to get a random polynomial with a root at x_3
    s_poly[0] -= &s_at_x3;
    // And sample a random blind
    let s_poly_blind = Blind(C::Scalar::random(&mut rng));

    // Write a commitment to the random polynomial to the transcript
    let s_poly_commitment = params.commit(&s_poly, s_poly_blind).to_affine();
    transcript.write_point(s_poly_commitment)?;

    // Challenge that will ensure that the prover cannot change P but can only
    // witness a random polynomial commitment that agrees with P at x_3, with high
    // probability.
    let xi = *transcript.squeeze_challenge_scalar::<()>();

    // Challenge that ensures that the prover did not interfere with the U term
    // in their commitments.
    let z = *transcript.squeeze_challenge_scalar::<()>();

    // We'll be opening `P' = P - [v] G_0 + [ξ] S` to ensure it has a root at
    // zero.
    let mut p_prime_poly = s_poly * xi + p_poly;
    let v = eval_polynomial(&p_prime_poly, x_3);
    p_prime_poly[0] -= &v;
    let p_prime_blind = s_poly_blind * Blind(xi) + p_blind;

    // This accumulates the synthetic blinding factor `f` starting
    // with the blinding factor for `P'`.
    let mut f = p_prime_blind.0;

    // Initialize the vector `p_prime` as the coefficients of the polynomial.
    let mut p_prime = p_prime_poly.values;
    assert_eq!(p_prime.len(), params.n as usize);

    // Initialize the vector `b` as the powers of `x_3`. The inner product of
    // `p_prime` and `b` is the evaluation of the polynomial at `x_3`.
    let mut b = Vec::with_capacity(1 << params.k);
    {
        let mut cur = C::Scalar::ONE;
        for _ in 0..(1 << params.k) {
            b.push(cur);
            cur *= &x_3;
        }
    }

    // Initialize the vector `G'` from the URS. We'll be progressively collapsing
    // this vector into smaller and smaller vectors until it is of length 1.
    let mut g_prime = params.g.clone();

    // Perform the inner product argument, round by round.
    for j in 0..params.k {
        let half = 1 << (params.k - j - 1); // half the length of `p_prime`, `b`, `G'`

        // Compute L, R
        //
        // TODO: If we modify multiexp to take "extra" bases, we could speed
        // this piece up a bit by combining the multiexps.
        let l_j = best_multiexp(&p_prime[half..], &g_prime[0..half]);
        let r_j = best_multiexp(&p_prime[0..half], &g_prime[half..]);
        let value_l_j = compute_inner_product(&p_prime[half..], &b[0..half]);
        let value_r_j = compute_inner_product(&p_prime[0..half], &b[half..]);
        let l_j_randomness = C::Scalar::random(&mut rng);
        let r_j_randomness = C::Scalar::random(&mut rng);
        let l_j = l_j + &best_multiexp(&[value_l_j * &z, l_j_randomness], &[params.u, params.w]);
        let r_j = r_j + &best_multiexp(&[value_r_j * &z, r_j_randomness], &[params.u, params.w]);
        let l_j = l_j.to_affine();
        let r_j = r_j.to_affine();

        // Feed L and R into the real transcript
        transcript.write_point(l_j)?;
        transcript.write_point(r_j)?;

        let u_j = *transcript.squeeze_challenge_scalar::<()>();
        let u_j_inv = u_j.invert().unwrap(); // TODO, bubble this up

        // Collapse `p_prime` and `b`.
        // TODO: parallelize
        #[allow(clippy::assign_op_pattern)]
        for i in 0..half {
            p_prime[i] = p_prime[i] + &(p_prime[i + half] * &u_j_inv);
            b[i] = b[i] + &(b[i + half] * &u_j);
        }
        p_prime.truncate(half);
        b.truncate(half);

        // Collapse `G'`
        parallel_generator_collapse(&mut g_prime, u_j);
        g_prime.truncate(half);

        // Update randomness (the synthetic blinding factor at the end)
        f += &(l_j_randomness * &u_j_inv);
        f += &(r_j_randomness * &u_j);
    }

    // We have fully collapsed `p_prime`, `b`, `G'`
    assert_eq!(p_prime.len(), 1);
    let c = p_prime[0];

    transcript.write_scalar(c)?;
    transcript.write_scalar(f)?;

    Ok(())
}
```

## 交易构建

### 交易结构

为了保证协议之间的兼容性，Orchard和其他协议仍然共享同一个交易结构，我们回到`CTransaction`，Orchard只为这个结构新增了一个`OrchardBundle`，

```cpp
class CTransaction
{
private:
    // ......
    OrchardBundle orchardBundle;
protected:
    // ......
public:
    // ......
}
```

### 构建过程

Orchard协议仍然使用之前的交易构建入口[TransactionBuilder::Build()](https://github.com/zcash/zcash/blob/3cec519ce498133e4bc88d59a9b704a3dc3b1977/src/transaction_builder.cpp#L483)，下面选取一部分，

```cpp
TransactionBuilderResult TransactionBuilder::Build()
{
    // ......

    //
    // Orchard
    //

    std::optional<orchard::UnauthorizedBundle> orchardBundle;
    if (orchardBuilder.has_value() && orchardBuilder->HasActions()) {
        auto bundle = orchardBuilder->Build();
        if (bundle.has_value()) {
            orchardBundle = std::move(bundle);
        } else {
            return TransactionBuilderResult("Failed to build Orchard bundle");
        }
    }

    //
    // Signatures
    //

    auto consensusBranchId = CurrentEpochBranchId(nHeight, consensusParams);

    // Empty output script.
    uint256 dataToBeSigned;
    try {
        if (orchardBundle.has_value()) {
            // Orchard is only usable with v5+ transactions.
            dataToBeSigned = ProduceZip244SignatureHash(mtx, tIns, orchardBundle.value());
        } else {
            CScript scriptCode;
            const PrecomputedTransactionData txdata(mtx, tIns);
            dataToBeSigned = SignatureHash(scriptCode, mtx, NOT_AN_INPUT, SIGHASH_ALL, 0, consensusBranchId, txdata);
        }
    } catch (std::ios_base::failure ex) {
        return TransactionBuilderResult("Could not construct signature hash: " + std::string(ex.what()));
    } catch (std::logic_error ex) {
        return TransactionBuilderResult("Could not construct signature hash: " + std::string(ex.what()));
    }

    if (orchardBundle.has_value()) {
        auto authorizedBundle = orchardBundle.value().ProveAndSign(
            orchardSpendingKeys, dataToBeSigned);
        if (authorizedBundle.has_value()) {
            mtx.orchardBundle = authorizedBundle.value();
        } else {
            return TransactionBuilderResult("Failed to create Orchard proof or signatures");
        }
    }

    // ......

    return TransactionBuilderResult(CTransaction(mtx));
}
```

这里的bundle生成直接调用到`orchardBuilder->Build()`，再调用到外部，

```rust
std::optional<UnauthorizedBundle> Builder::Build() {
    if (!inner) {
        throw std::logic_error("orchard::Builder has already been used");
    }

    auto bundle = orchard_builder_build(inner.release());
    if (bundle == nullptr) {
        return std::nullopt;
    } else {
        return UnauthorizedBundle(bundle);
    }
}
```

签名使用如下名为`Zip244`的匿名签名算法，也调用到了外部，

```cpp
uint256 ProduceZip244SignatureHash(
    const CTransaction& tx,
    const std::vector<CTxOut>& allPrevOutputs,
    const orchard::UnauthorizedBundle& orchardBundle)
{
    uint256 dataToBeSigned;
    PrecomputedTransactionData local(tx, allPrevOutputs);
    if (!zcash_builder_zip244_shielded_signature_digest(
        local.preTx.release(),
        orchardBundle.inner.get(),
        dataToBeSigned.begin()))
    {
        throw std::logic_error("ZIP 225 signature hash failed");
    }
    return dataToBeSigned;
}
```

```cpp
pub extern "C" fn zcash_builder_zip244_shielded_signature_digest(
    precomputed_tx: *mut PrecomputedTxParts,
    bundle: *const Bundle<InProgress<Unproven, Unauthorized>, Amount>,
    sighash_ret: *mut [u8; 32],
) -> bool {
    let precomputed_tx = if !precomputed_tx.is_null() {
        unsafe { Box::from_raw(precomputed_tx) }
    } else {
        error!("Invalid precomputed transaction");
        return false;
    };
    if matches!(
        precomputed_tx.tx.version(),
        TxVersion::Sprout(_) | TxVersion::Overwinter | TxVersion::Sapling,
    ) {
        error!("Cannot calculate ZIP 244 digest for pre-v5 transaction");
        return false;
    }
    let bundle = unsafe { bundle.as_ref().unwrap() };

    struct Signable {}
    impl Authorization for Signable {
        type TransparentAuth = TransparentAuth;
        type SaplingAuth = sapling::Authorized;
        type OrchardAuth = InProgress<Unproven, Unauthorized>;
    }

    let txdata: TransactionData<Signable> =
        precomputed_tx
            .tx
            .map_bundles(|b| b, |b| b, |_| Some(bundle.clone()));
    let txid_parts = txdata.digest(TxIdDigester);

    let sighash = v5_signature_hash(&txdata, &SignableInput::Shielded, &txid_parts);

    // `v5_signature_hash` output is always 32 bytes.
    *unsafe { &mut *sighash_ret } = sighash.as_ref().try_into().unwrap();
    true
}
```

先看bundle生成，我们可以在[zcash/orchard/src/builder.rs](https://github.com/zcash/orchard/blob/e2bfd99454b171e1a0c9fb3e128f09c023ea9700/src/builder.rs)找到入口，

```rust
/// Builds the action.
///
/// Defined in [Zcash Protocol Spec § 4.7.3: Sending Notes (Orchard)][orchardsend].
///
/// [orchardsend]: https://zips.z.cash/protocol/nu5.pdf#orchardsend
fn build(self, mut rng: impl RngCore) -> (Action<SigningMetadata>, Circuit) {
    let v_net = self.value_sum();
    let cv_net = ValueCommitment::derive(v_net, self.rcv.clone());

    let nf_old = self.spend.note.nullifier(&self.spend.fvk);
    let ak: SpendValidatingKey = self.spend.fvk.clone().into();
    let alpha = pallas::Scalar::random(&mut rng);
    let rk = ak.randomize(&alpha);

    let note = Note::new(self.output.recipient, self.output.value, nf_old, &mut rng);
    let cm_new = note.commitment();
    let cmx = cm_new.into();

    let encryptor = OrchardNoteEncryption::new(
        self.output.ovk,
        note,
        self.output.recipient,
        self.output.memo.unwrap_or_else(|| {
            let mut memo = [0; 512];
            memo[0] = 0xf6;
            memo
        }),
    );

    let encrypted_note = TransmittedNoteCiphertext {
        epk_bytes: encryptor.epk().to_bytes().0,
        enc_ciphertext: encryptor.encrypt_note_plaintext(),
        out_ciphertext: encryptor.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut rng),
    };

    (
        Action::from_parts(
            nf_old,
            rk,
            cmx,
            encrypted_note,
            cv_net,
            SigningMetadata {
                dummy_ask: self.spend.dummy_sk.as_ref().map(SpendAuthorizingKey::from),
                parts: SigningParts { ak, alpha },
            },
        ),
        Circuit::from_action_context_unchecked(self.spend, note, alpha, self.rcv),
    )
}
```

## Orchard验证

### 上下文无关验证

### 上下文验证

### 区块连接

## 小结