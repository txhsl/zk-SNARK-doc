# Zcash Part5

## Sapling

看完了Sprout，我们来看Sapling，这个协议只对每一个input和output生成分别的证明。在上一节中我们知道，Sprout协议处理复杂交易时JoinSplit要完成零钱Note的反复铸造和销毁，毫无疑问在性能上有很大的提升空间。

针对Sprout协议存在的性能短板，Zcash提出了作为改进的Sapling协议。在之前的内容中，我们已经知道Sapling是在Sprout基础上重建的协议，甚至地址上可以相互兼容，因此它们的相似程度也非常高。

### Zcash入口

为了把使用Rust编写的新内容放进原有使用C++编写的Sprout节点中，Sapling的定义添加在[zcash/zcash/src/rust/src](https://github.com/zcash/zcash/tree/master/src/rust/src)下。我们先看Sapling。

先找到Sapling证明的Prover入口，它在[zcash/zcash/src/rust/src/sapling.rs](https://github.com/zcash/zcash/blob/3ef12e98c1ec22372cb971f28eaf18cbb7bbb1f6/src/rust/src/sapling.rs#L263)，对应的Spend代码如下，

```rust
fn create_spend_proof(
    &mut self,
    ak: &[u8; 32],
    nsk: &[u8; 32],
    diversifier: &[u8; 11],
    rcm: &[u8; 32],
    ar: &[u8; 32],
    value: u64,
    anchor: &[u8; 32],
    merkle_path: &[u8; 1 + 33 * SAPLING_TREE_DEPTH + 8],
    cv: &mut [u8; 32],
    rk_out: &mut [u8; 32],
    zkproof: &mut [u8; GROTH_PROOF_SIZE],
) -> bool {
    // Grab `ak` from the caller, which should be a point.
    let ak = match de_ct(jubjub::ExtendedPoint::from_bytes(ak)) {
        Some(p) => p,
        None => return false,
    };

    // `ak` should be prime order.
    let ak = match de_ct(ak.into_subgroup()) {
        Some(p) => p,
        None => return false,
    };

    // Grab `nsk` from the caller
    let nsk = match de_ct(jubjub::Scalar::from_bytes(nsk)) {
        Some(p) => p,
        None => return false,
    };

    // Construct the proof generation key
    let proof_generation_key = ProofGenerationKey { ak, nsk };

    // Grab the diversifier from the caller
    let diversifier = Diversifier(*diversifier);

    // The caller chooses the note randomness
    // If this is after ZIP 212, the caller has calculated rcm, and we don't need to call
    // Note::derive_esk, so we just pretend the note was using this rcm all along.
    let rseed = match de_ct(jubjub::Scalar::from_bytes(rcm)) {
        Some(p) => Rseed::BeforeZip212(p),
        None => return false,
    };

    // The caller also chooses the re-randomization of ak
    let ar = match de_ct(jubjub::Scalar::from_bytes(ar)) {
        Some(p) => p,
        None => return false,
    };

    // We need to compute the anchor of the Spend.
    let anchor = match de_ct(bls12_381::Scalar::from_bytes(anchor)) {
        Some(p) => p,
        None => return false,
    };

    // Parse the Merkle path from the caller
    let merkle_path = match MerklePath::from_slice(merkle_path) {
        Ok(w) => w,
        Err(_) => return false,
    };

    // Create proof
    let (proof, value_commitment, rk) = self
        .0
        .spend_proof(
            proof_generation_key,
            diversifier,
            rseed,
            ar,
            value,
            anchor,
            merkle_path,
            unsafe { SAPLING_SPEND_PARAMS.as_ref() }.unwrap(),
            &prepare_verifying_key(unsafe { SAPLING_SPEND_VK.as_ref() }.unwrap()),
        )
        .expect("proving should not fail");

    // Write value commitment to caller
    *cv = value_commitment.to_bytes();

    // Write proof out to caller
    proof
        .write(&mut zkproof[..])
        .expect("should be able to serialize a proof");

    // Write out `rk` to the caller
    rk.write(&mut rk_out[..])
        .expect("should be able to write to rk_out");

    true
}
```

以上是对input的证明入口，这里接收数据后做一些验证，用`ask`、`nsk`生成了证明生成密钥`proof_generation_key`，然后向外部调用，将返回的证明写入`zkproof`返回，同时返回的还有公开参数`cv`和`rk`。

这里没有Sprout一样的参数检测和说明，简单介绍一下使用的参数，可以回看Part1，

1. expanded spending key中的`ask`、`nsk`，`ask`这里写作了`ak`；
3. note中的`d`、`rcm`和`v`，`v`这里写作了`value`，`d`写作了`diversifier`；
4. spend note的`anchor`，即Sapling Incremental Tree的merkel root；
5. 一个指定的随机种子`alpha`，这里写作了`ar`；
6. spend note commitment的merkle tree path，这里写作了`merkle_path`。

同一位置的下方还有对output的证明入口，

```rust
fn create_output_proof(
    &mut self,
    esk: &[u8; 32],
    payment_address: &[u8; 43],
    rcm: &[u8; 32],
    value: u64,
    cv: &mut [u8; 32],
    zkproof: &mut [u8; GROTH_PROOF_SIZE],
) -> bool {
    // Grab `esk`, which the caller should have constructed for the DH key exchange.
    let esk = match de_ct(jubjub::Scalar::from_bytes(esk)) {
        Some(p) => p,
        None => return false,
    };

    // Grab the payment address from the caller
    let payment_address = match PaymentAddress::from_bytes(payment_address) {
        Some(pa) => pa,
        None => return false,
    };

    // The caller provides the commitment randomness for the output note
    let rcm = match de_ct(jubjub::Scalar::from_bytes(rcm)) {
        Some(p) => p,
        None => return false,
    };

    // Create proof
    let (proof, value_commitment) = self.0.output_proof(
        esk,
        payment_address,
        rcm,
        value,
        unsafe { SAPLING_OUTPUT_PARAMS.as_ref() }.unwrap(),
    );

    // Write the proof out to the caller
    proof
        .write(&mut zkproof[..])
        .expect("should be able to serialize a proof");

    // Write the value commitment to the caller
    *cv = value_commitment.to_bytes();

    true
}
```

和上面spend proof不同的是，这里使用了额外的参数`esk`、`payment_address`，前者是secret sharing中的加密私钥，后者是Sapling中的接收地址。

### Librustzcash中转

#### 参数准备

这里生成证明的调用是`spend_proof`，我们可以在[zcash/librustzcash/zcash_proofs/src/sapling/prover.rs](https://github.com/zcash/librustzcash/blob/23922ca290e300db3252e484dfdcd18c17ed75ee/zcash_proofs/src/sapling/prover.rs#L48)找到，对应下面的代码，

```rust
/// Create the value commitment, re-randomized key, and proof for a Sapling
/// SpendDescription, while accumulating its value commitment randomness
/// inside the context for later use.
pub fn spend_proof(
    &mut self,
    proof_generation_key: ProofGenerationKey,
    diversifier: Diversifier,
    rseed: Rseed,
    ar: jubjub::Fr,
    value: u64,
    anchor: bls12_381::Scalar,
    merkle_path: MerklePath<Node>,
    proving_key: &Parameters<Bls12>,
    verifying_key: &PreparedVerifyingKey<Bls12>,
) -> Result<(Proof<Bls12>, jubjub::ExtendedPoint, PublicKey), ()> {
    // Initialize secure RNG
    let mut rng = OsRng;

    // We create the randomness of the value commitment
    let rcv = jubjub::Fr::random(&mut rng);

    // Accumulate the value commitment randomness in the context
    {
        let mut tmp = rcv;
        tmp.add_assign(&self.bsk);

        // Update the context
        self.bsk = tmp;
    }

    // Construct the value commitment
    let value_commitment = ValueCommitment {
        value,
        randomness: rcv,
    };

    // Construct the viewing key
    let viewing_key = proof_generation_key.to_viewing_key();

    // Construct the payment address with the viewing key / diversifier
    let payment_address = viewing_key.to_payment_address(diversifier).ok_or(())?;

    // This is the result of the re-randomization, we compute it for the caller
    let rk = PublicKey(proof_generation_key.ak.into()).randomize(ar, SPENDING_KEY_GENERATOR);

    // Let's compute the nullifier while we have the position
    let note = Note {
        value,
        g_d: diversifier.g_d().expect("was a valid diversifier before"),
        pk_d: *payment_address.pk_d(),
        rseed,
    };

    let nullifier = note.nf(&viewing_key.nk, merkle_path.position);

    // We now have the full witness for our circuit
    let instance = Spend {
        value_commitment: Some(value_commitment.clone()),
        proof_generation_key: Some(proof_generation_key),
        payment_address: Some(payment_address),
        commitment_randomness: Some(note.rcm()),
        ar: Some(ar),
        auth_path: merkle_path
            .auth_path
            .iter()
            .map(|(node, b)| Some(((*node).into(), *b)))
            .collect(),
        anchor: Some(anchor),
    };

    // Create proof
    let proof =
        create_random_proof(instance, proving_key, &mut rng).expect("proving should not fail");

    // Try to verify the proof:
    // Construct public input for circuit
    let mut public_input = [bls12_381::Scalar::zero(); 7];
    {
        let affine = rk.0.to_affine();
        let (u, v) = (affine.get_u(), affine.get_v());
        public_input[0] = u;
        public_input[1] = v;
    }
    {
        let affine = jubjub::ExtendedPoint::from(value_commitment.commitment()).to_affine();
        let (u, v) = (affine.get_u(), affine.get_v());
        public_input[2] = u;
        public_input[3] = v;
    }
    public_input[4] = anchor;

    // Add the nullifier through multiscalar packing
    {
        let nullifier = multipack::bytes_to_bits_le(&nullifier.0);
        let nullifier = multipack::compute_multipacking(&nullifier);

        assert_eq!(nullifier.len(), 2);

        public_input[5] = nullifier[0];
        public_input[6] = nullifier[1];
    }

    // Verify the proof
    verify_proof(verifying_key, &proof, &public_input[..]).map_err(|_| ())?;

    // Compute value commitment
    let value_commitment: jubjub::ExtendedPoint = value_commitment.commitment().into();

    // Accumulate the value commitment in the context
    self.cv_sum += value_commitment;

    Ok((proof, value_commitment, rk))
}
```

以上方法发挥和Sprout中`create_proof`类似的作用，准备好Groth16需要的电路和参数，收到证明后处理nullifier和value commitment。详细来说，依次计算了，

1. `rcv` - Value commitment中的随机因子；
2. `bsk` - Binding signature的签名私钥；
3. `value_commitment` - 对本次spend的value数值做出的承诺；
4. `viewing_key` - Note的使用者，也就是本次证明的请求者使用的viewing key；
5. `payment_address` - 请求者的支付地址。

我们还记得Sprout中JoinSplit电路的公开参数包括anchor root、`h_sig`、nullifier、`mac`、commitment以及`vpub_old`和`vpub_new`。而这里Spend电路的公开参数则是anchor root、`rk`、nullifier和value commitment。关于`rk`和签名，我们后面再提到。

比较重要的是，

1. `self.cv_sum += value_commitment;`，我们看到commitment被用于value的平衡验证，这一点不再是通过证明完成；
2. `let rcv = jubjub::Fr::random(&mut rng);`，这个随机元被用于混淆保护`value`的值不被推测，而它的和直接生成了`bsk`；
3. `value_commitment`代替`value`成为了证明电路的输入，进一步可以看到电路的输入不再包含透露隐私的原始数据，这意味着Sapling的证明计算过程可以被委托。

`ValueCommitment`的[定义](https://github.com/zcash/librustzcash/blob/23922ca290e300db3252e484dfdcd18c17ed75ee/zcash_primitives/src/sapling/value.rs#L107)如下，

```rust
#[derive(Clone, Debug)]
pub struct ValueCommitment(jubjub::ExtendedPoint);

impl ValueCommitment {
    /// Derives a `ValueCommitment` by $\mathsf{ValueCommit^{Sapling}}$.
    ///
    /// Defined in [Zcash Protocol Spec § 5.4.8.3: Homomorphic Pedersen commitments (Sapling and Orchard)][concretehomomorphiccommit].
    ///
    /// [concretehomomorphiccommit]: https://zips.z.cash/protocol/protocol.pdf#concretehomomorphiccommit
    /// 假定G和H是两个提前初始化的生成元，则数值承诺Comm = k * G + r * H
    pub fn derive(value: NoteValue, rcv: ValueCommitTrapdoor) -> Self {
        let cv = (VALUE_COMMITMENT_VALUE_GENERATOR * jubjub::Scalar::from(value.0))
            + (VALUE_COMMITMENT_RANDOMNESS_GENERATOR * rcv.0);

        ValueCommitment(cv.into())
    }

    /// Returns the inner Jubjub point representing this value commitment.
    ///
    /// This is public for access by `zcash_proofs`.
    pub fn as_inner(&self) -> &jubjub::ExtendedPoint {
        &self.0
    }

    /// Deserializes a value commitment from its byte representation.
    ///
    /// Returns `None` if `bytes` is an invalid representation of a Jubjub point, or the
    /// resulting point is of small order.
    ///
    /// This method can be used to enforce the "not small order" consensus rules defined
    /// in [Zcash Protocol Spec § 4.4: Spend Descriptions][spenddesc] and
    /// [§ 4.5: Output Descriptions][outputdesc].
    ///
    /// [spenddesc]: https://zips.z.cash/protocol/protocol.pdf#spenddesc
    /// [outputdesc]: https://zips.z.cash/protocol/protocol.pdf#outputdesc
    pub fn from_bytes_not_small_order(bytes: &[u8; 32]) -> CtOption<ValueCommitment> {
        jubjub::ExtendedPoint::from_bytes(bytes)
            .and_then(|cv| CtOption::new(ValueCommitment(cv), !cv.is_small_order()))
    }

    /// Serializes this value commitment to its canonical byte representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}
```

当然`output_proof`也出现在相同的位置，

```rust
/// Create the value commitment and proof for a Sapling OutputDescription,
/// while accumulating its value commitment randomness inside the context
/// for later use.
pub fn output_proof(
    &mut self,
    esk: jubjub::Fr,
    payment_address: PaymentAddress,
    rcm: jubjub::Fr,
    value: u64,
    proving_key: &Parameters<Bls12>,
) -> (Proof<Bls12>, jubjub::ExtendedPoint) {
    // Initialize secure RNG
    let mut rng = OsRng;

    // We construct ephemeral randomness for the value commitment. This
    // randomness is not given back to the caller, but the synthetic
    // blinding factor `bsk` is accumulated in the context.
    let rcv = jubjub::Fr::random(&mut rng);

    // Accumulate the value commitment randomness in the context
    {
        let mut tmp = rcv.neg(); // Outputs subtract from the total.
        tmp.add_assign(&self.bsk);

        // Update the context
        self.bsk = tmp;
    }

    // Construct the value commitment for the proof instance
    let value_commitment = ValueCommitment {
        value,
        randomness: rcv,
    };

    // We now have a full witness for the output proof.
    let instance = Output {
        value_commitment: Some(value_commitment.clone()),
        payment_address: Some(payment_address),
        commitment_randomness: Some(rcm),
        esk: Some(esk),
    };

    // Create proof
    let proof =
        create_random_proof(instance, proving_key, &mut rng).expect("proving should not fail");

    // Compute the actual value commitment
    let value_commitment: jubjub::ExtendedPoint = value_commitment.commitment().into();

    // Accumulate the value commitment in the context. We do this to check internal consistency.
    self.cv_sum -= value_commitment; // Outputs subtract from the total.

    (proof, value_commitment)
}
```

依然关注`bsk`和`cv_sum`，它们在这里做的是减法，后面会用到。此外，这里返回的公开参数仅有`value_commitment`，没有对生成的证明进行验证。

#### 证明电路

我们可以在[zcash/librustzcash/zcash_proofs/src/circuit/sapling.rs](https://github.com/zcash/librustzcash/blob/ded14adbb3b0f5c80bf998c84073f2172de7beaa/zcash_proofs/src/circuit/sapling.rs#L137)找到Spend电路的定义，对应代码如下，

```rust
impl Circuit<bls12_381::Scalar> for Spend {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Prover witnesses ak (ensures that it's on the curve)
        // 见证ak为椭圆曲线有效点
        let ak = ecc::EdwardsPoint::witness(
            cs.namespace(|| "ak"),
            self.proof_generation_key.as_ref().map(|k| k.ak.into()),
        )?;

        // There are no sensible attacks on small order points
        // of ak (that we're aware of!) but it's a cheap check,
        // so we do it.
        // 见证ak为理想范围内的取值
        ak.assert_not_small_order(cs.namespace(|| "ak not small order"))?;

        // Rerandomize ak and expose it as an input to the circuit
        // 从ak随机生成rk作为公开输入
        {
            let ar = boolean::field_into_boolean_vec_le(cs.namespace(|| "ar"), self.ar)?;

            // Compute the randomness in the exponent
            let ar = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of randomization for the signing key"),
                &SPENDING_KEY_GENERATOR,
                &ar,
            )?;

            // rk = ak + ar
            let rk = ak.add(cs.namespace(|| "computation of rk"), &ar)?;

            rk.inputize(cs.namespace(|| "rk"))?;
        }

        // Compute nk = [nsk] ProofGenerationKey
        // 从私钥nsk计算nk
        let nk;
        {
            // Witness nsk as bits
            let nsk = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "nsk"),
                self.proof_generation_key.as_ref().map(|k| k.nsk),
            )?;

            // NB: We don't ensure that the bit representation of nsk
            // is "in the field" (jubjub::Fr) because it's not used
            // except to demonstrate the prover knows it. If they know
            // a congruency then that's equivalent.

            // Compute nk = [nsk] ProvingPublicKey
            nk = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of nk"),
                &PROOF_GENERATION_KEY_GENERATOR,
                &nsk,
            )?;
        }

        // This is the "viewing key" preimage for CRH^ivk
        // 组装ivk生成元ivk_preimage = ak.extend(nk)，然后做blake2s哈希获得ivk
        let mut ivk_preimage = vec![];

        // Place ak in the preimage for CRH^ivk
        ivk_preimage.extend(ak.repr(cs.namespace(|| "representation of ak"))?);

        // This is the nullifier preimage for PRF^nf
        let mut nf_preimage = vec![];

        // Extend ivk and nf preimages with the representation of
        // nk.
        {
            let repr_nk = nk.repr(cs.namespace(|| "representation of nk"))?;

            ivk_preimage.extend(repr_nk.iter().cloned());
            nf_preimage.extend(repr_nk);
        }

        assert_eq!(ivk_preimage.len(), 512);
        assert_eq!(nf_preimage.len(), 256);

        // Compute the incoming viewing key ivk
        let mut ivk = blake2s::blake2s(
            cs.namespace(|| "computation of ivk"),
            &ivk_preimage,
            constants::CRH_IVK_PERSONALIZATION,
        )?;

        // drop_5 to ensure it's in the field
        // 做一个有效验证
        ivk.truncate(jubjub::Fr::CAPACITY as usize);

        // Witness g_d, checking that it's on the curve.
        // 见证g_d为椭圆曲线有效点
        let g_d = {
            ecc::EdwardsPoint::witness(
                cs.namespace(|| "witness g_d"),
                self.payment_address
                    .as_ref()
                    .and_then(|a| a.g_d().map(jubjub::ExtendedPoint::from)),
            )?
        };

        // Check that g_d is not small order. Technically, this check
        // is already done in the Output circuit, and this proof ensures
        // g_d is bound to a product of that check, but for defense in
        // depth let's check it anyway. It's cheap.
        g_d.assert_not_small_order(cs.namespace(|| "g_d not small order"))?;

        // Compute pk_d = g_d^ivk
        // 计算pk_d
        let pk_d = g_d.mul(cs.namespace(|| "compute pk_d"), &ivk)?;

        // Compute note contents:
        // value (in big endian) followed by g_d and pk_d
        // 接下来组装note = value_bits.extend(g_d).extend(pk_d)，也就是secret sharing的内容
        let mut note_contents = vec![];

        // Handle the value; we'll need it later for the
        // dummy input check.
        // 将value commitment转换成linear combination形式
        let mut value_num = num::Num::zero();
        {
            // Get the value in little-endian bit order
            let value_bits = expose_value_commitment(
                cs.namespace(|| "value commitment"),
                self.value_commitment,
            )?;

            // Compute the note's value as a linear combination
            // of the bits.
            let mut coeff = bls12_381::Scalar::one();
            for bit in &value_bits {
                value_num = value_num.add_bool_with_coeff(CS::one(), bit, coeff);
                coeff = coeff.double();
            }

            // Place the value in the note
            note_contents.extend(value_bits);
        }

        // Place g_d in the note
        note_contents.extend(g_d.repr(cs.namespace(|| "representation of g_d"))?);

        // Place pk_d in the note
        note_contents.extend(pk_d.repr(cs.namespace(|| "representation of pk_d"))?);

        assert_eq!(
            note_contents.len(),
            64 + // value
            256 + // g_d
            256 // p_d
        );

        // Compute the hash of the note contents
        // 做note的哈希cm
        let mut cm = pedersen_hash::pedersen_hash(
            cs.namespace(|| "note content hash"),
            pedersen_hash::Personalization::NoteCommitment,
            &note_contents,
        )?;

        // 引入随机量rcm，并添加到cm中
        {
            // Booleanize the randomness for the note commitment
            let rcm = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "rcm"),
                self.commitment_randomness,
            )?;

            // Compute the note commitment randomness in the exponent
            let rcm = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of commitment randomness"),
                &NOTE_COMMITMENT_RANDOMNESS_GENERATOR,
                &rcm,
            )?;

            // Randomize the note commitment. Pedersen hashes are not
            // themselves hiding commitments.
            cm = cm.add(cs.namespace(|| "randomization of note commitment"), &rcm)?;
        }

        // This will store (least significant bit first)
        // the position of the note in the tree, for use
        // in nullifier computation.
        let mut position_bits = vec![];

        // This is an injective encoding, as cur is a
        // point in the prime order subgroup.
        let mut cur = cm.get_u().clone();

        // Ascend the merkle tree authentication path
        // 见证merkle tree path的有效性，cur取值和椭圆曲线有关
        for (i, e) in self.auth_path.into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

            // Determines if the current subtree is the "right" leaf at this
            // depth of the tree.
            let cur_is_right = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                cs.namespace(|| "position bit"),
                e.map(|e| e.1),
            )?);

            // Push this boolean for nullifier computation later
            position_bits.push(cur_is_right.clone());

            // Witness the authentication path element adjacent
            // at this depth.
            let path_element =
                num::AllocatedNum::alloc(cs.namespace(|| "path element"), || Ok(e.get()?.0))?;

            // Swap the two if the current subtree is on the right
            let (ul, ur) = num::AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of preimage"),
                &cur,
                &path_element,
                &cur_is_right,
            )?;

            // We don't need to be strict, because the function is
            // collision-resistant. If the prover witnesses a congruency,
            // they will be unable to find an authentication path in the
            // tree with high probability.
            let mut preimage = vec![];
            preimage.extend(ul.to_bits_le(cs.namespace(|| "ul into bits"))?);
            preimage.extend(ur.to_bits_le(cs.namespace(|| "ur into bits"))?);

            // Compute the new subtree value
            // 计算新的哈希值
            cur = pedersen_hash::pedersen_hash(
                cs.namespace(|| "computation of pedersen hash"),
                pedersen_hash::Personalization::MerkleTree(i),
                &preimage,
            )?
            .get_u()
            .clone(); // Injective encoding
        }

        {
            // 取出输入的anchor root
            let real_anchor_value = self.anchor;

            // Allocate the "real" anchor that will be exposed.
            let rt = num::AllocatedNum::alloc(cs.namespace(|| "conditional anchor"), || {
                Ok(*real_anchor_value.get()?)
            })?;

            // (cur - rt) * value = 0
            // if value is zero, cur and rt can be different
            // if value is nonzero, they must be equal
            // 见证输入值和计算值相等
            cs.enforce(
                || "conditionally enforce correct root",
                |lc| lc + cur.get_variable() - rt.get_variable(),
                |lc| lc + &value_num.lc(bls12_381::Scalar::one()),
                |lc| lc,
            );

            // Expose the anchor
            rt.inputize(cs.namespace(|| "anchor"))?;
        }

        // Compute the cm + g^position for preventing
        // faerie gold attacks
        // 将position_bits加入cm，然后计算nullifier
        let mut rho = cm;
        {
            // Compute the position in the exponent
            let position = ecc::fixed_base_multiplication(
                cs.namespace(|| "g^position"),
                &NULLIFIER_POSITION_GENERATOR,
                &position_bits,
            )?;

            // Add the position to the commitment
            rho = rho.add(cs.namespace(|| "faerie gold prevention"), &position)?;
        }

        // Let's compute nf = BLAKE2s(nk || rho)
        nf_preimage.extend(rho.repr(cs.namespace(|| "representation of rho"))?);

        assert_eq!(nf_preimage.len(), 512);

        // Compute nf
        let nf = blake2s::blake2s(
            cs.namespace(|| "nf computation"),
            &nf_preimage,
            constants::PRF_NF_PERSONALIZATION,
        )?;

        multipack::pack_into_inputs(cs.namespace(|| "pack nullifier"), &nf)
    }
}
```

以上电路按照顺序做了以下事情：

1. 检查`ak`、`g_d`，计算`rk`、`nk`、`ivk`、`pk_d`等密钥；
2. 用`value`、`g_d`和`pk_d`组装note，计算哈希获得commitment `cm`；
3. 逐层见证merkle tree path，最后计算一个新的subtree value和`rt`比较；
4. 给`cm`添加随机量`rcm`获得`rho`，再添加`position_bits`从而计算nullifier；
5. 准备公开`rk`、`rt`、`cm`、`nf`。

代码中调用了部分外部的电路，比如格式转换的[`boolean::field_into_boolean_vec_le`](https://github.com/zkcrypto/bellman/blob/2759d930622a7f18b83a905c9f054d52a0bbe748/src/gadgets/boolean.rs#L300)，

```rust
pub fn field_into_boolean_vec_le<
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
    F: PrimeFieldBits,
>(
    cs: CS,
    value: Option<F>,
) -> Result<Vec<Boolean>, SynthesisError> {
    let v = field_into_allocated_bits_le::<Scalar, CS, F>(cs, value)?;

    Ok(v.into_iter().map(Boolean::from).collect())
}

pub fn field_into_allocated_bits_le<
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
    F: PrimeFieldBits,
>(
    mut cs: CS,
    value: Option<F>,
) -> Result<Vec<AllocatedBit>, SynthesisError> {
    // Deconstruct in big-endian bit order
    let values = match value {
        Some(ref value) => {
            let field_char = F::char_le_bits();
            let mut field_char = field_char.iter().by_refs().rev();

            let mut tmp = Vec::with_capacity(F::NUM_BITS as usize);

            let mut found_one = false;
            for b in value.to_le_bits().iter().by_vals().rev() {
                // Skip leading bits
                found_one |= field_char.next().unwrap();
                if !found_one {
                    continue;
                }

                tmp.push(Some(b));
            }

            assert_eq!(tmp.len(), F::NUM_BITS as usize);

            tmp
        }
        None => vec![None; F::NUM_BITS as usize],
    };

    // Allocate in little-endian order
    let bits = values
        .into_iter()
        .rev()
        .enumerate()
        .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("bit {}", i)), b))
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    Ok(bits)
}
```

格式转换的[`boolean::u64_into_boolean_vec_le`](https://github.com/zkcrypto/bellman/blob/2759d930622a7f18b83a905c9f054d52a0bbe748/src/gadgets/boolean.rs#L269)，

```rust
pub fn u64_into_boolean_vec_le<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: Option<u64>,
) -> Result<Vec<Boolean>, SynthesisError> {
    let values = match value {
        Some(ref value) => {
            let mut tmp = Vec::with_capacity(64);

            for i in 0..64 {
                tmp.push(Some(*value >> i & 1 == 1));
            }

            tmp
        }
        None => vec![None; 64],
    };

    let bits = values
        .into_iter()
        .enumerate()
        .map(|(i, b)| {
            Ok(Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("bit {}", i)),
                b,
            )?))
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    Ok(bits)
}
```

包含运算的[`num::Num::add_bool_with_coeff`](https://github.com/zkcrypto/bellman/blob/2759d930622a7f18b83a905c9f054d52a0bbe748/src/gadgets/num.rs#L398)，

```rust
pub fn add_bool_with_coeff(self, one: Variable, bit: &Boolean, coeff: Scalar) -> Self {
    let newval = match (self.value, bit.get_value()) {
        (Some(mut curval), Some(bval)) => {
            if bval {
                curval.add_assign(&coeff);
            }
            Some(curval)
        }
        _ => None,
    };

    Num {
        value: newval,
        lc: self.lc + &bit.lc(one, coeff),
    }
}
```

提取数值的[`num::AllocatedNum::alloc`](https://github.com/zkcrypto/bellman/blob/2759d930622a7f18b83a905c9f054d52a0bbe748/src/gadgets/num.rs#L26)，

```rust
pub fn alloc<CS, F>(mut cs: CS, value: F) -> Result<Self, SynthesisError>
where
    CS: ConstraintSystem<Scalar>,
    F: FnOnce() -> Result<Scalar, SynthesisError>,
{
    let mut new_value = None;
    let var = cs.alloc(
        || "num",
        || {
            let tmp = value()?;
            new_value = Some(tmp);
            Ok(tmp)
        },
    )?;

    Ok(AllocatedNum {
        value: new_value,
        variable: var,
    })
 }
```

条件判断的[`num::AllocatedNum::conditionally_reverse`](https://github.com/zkcrypto/bellman/blob/2759d930622a7f18b83a905c9f054d52a0bbe748/src/gadgets/num.rs#L317)，

```rust
/// Takes two allocated numbers (a, b) and returns
/// (b, a) if the condition is true, and (a, b)
/// otherwise.
pub fn conditionally_reverse<CS>(
    mut cs: CS,
    a: &Self,
    b: &Self,
    condition: &Boolean,
) -> Result<(Self, Self), SynthesisError>
where
    CS: ConstraintSystem<Scalar>,
{
    let c = Self::alloc(cs.namespace(|| "conditional reversal result 1"), || {
        if *condition.get_value().get()? {
            Ok(*b.value.get()?)
        } else {
            Ok(*a.value.get()?)
        }
    })?;

    cs.enforce(
        || "first conditional reversal",
        |lc| lc + a.variable - b.variable,
        |_| condition.lc(CS::one(), Scalar::one()),
        |lc| lc + a.variable - c.variable,
    );

    let d = Self::alloc(cs.namespace(|| "conditional reversal result 2"), || {
        if *condition.get_value().get()? {
            Ok(*a.value.get()?)
        } else {
            Ok(*b.value.get()?)
        }
    })?;

    cs.enforce(
        || "second conditional reversal",
        |lc| lc + b.variable - a.variable,
        |_| condition.lc(CS::one(), Scalar::one()),
        |lc| lc + b.variable - d.variable,
    );

    Ok((c, d))
}
```

见证value commitment的`expose_value_commitment`，

```rust
/// Exposes a Pedersen commitment to the value as an
/// input to the circuit
fn expose_value_commitment<CS>(
    mut cs: CS,
    value_commitment_opening: Option<ValueCommitmentOpening>,
) -> Result<Vec<boolean::Boolean>, SynthesisError>
where
    CS: ConstraintSystem<bls12_381::Scalar>,
{
    // Booleanize the value into little-endian bit order
    let value_bits = boolean::u64_into_boolean_vec_le(
        cs.namespace(|| "value"),
        value_commitment_opening.as_ref().map(|c| c.value),
    )?;

    // Compute the note value in the exponent
    let value = ecc::fixed_base_multiplication(
        cs.namespace(|| "compute the value in the exponent"),
        &VALUE_COMMITMENT_VALUE_GENERATOR,
        &value_bits,
    )?;

    // Booleanize the randomness. This does not ensure
    // the bit representation is "in the field" because
    // it doesn't matter for security.
    let rcv = boolean::field_into_boolean_vec_le(
        cs.namespace(|| "rcv"),
        value_commitment_opening.as_ref().map(|c| c.randomness),
    )?;

    // Compute the randomness in the exponent
    let rcv = ecc::fixed_base_multiplication(
        cs.namespace(|| "computation of rcv"),
        &VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
        &rcv,
    )?;

    // Compute the Pedersen commitment to the value
    let cv = value.add(cs.namespace(|| "computation of cv"), &rcv)?;

    // Expose the commitment as an input to the circuit
    cv.inputize(cs.namespace(|| "commitment point"))?;

    Ok(value_bits)
}
```

其他关于`ecc::EdwardsPoint`、`pedersen_hash`、`blake2s`的电路，以及相关的操作`add`、`mul`、`assert_not_small_order`、`fixed_base_multiplication`和`inputize`等等，我们在后面单独介绍。

同一文件中，我们还可以找到Sapling使用的Output电路，

```rust
impl Circuit<bls12_381::Scalar> for Output {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Let's start to construct our note, which contains
        // value (big endian)
        let mut note_contents = vec![];

        // Expose the value commitment and place the value
        // in the note.
        note_contents.extend(expose_value_commitment(
            cs.namespace(|| "value commitment"),
            self.value_commitment,
        )?);

        // Let's deal with g_d
        {
            // Prover witnesses g_d, ensuring it's on the
            // curve.
            let g_d = ecc::EdwardsPoint::witness(
                cs.namespace(|| "witness g_d"),
                self.payment_address
                    .as_ref()
                    .and_then(|a| a.g_d().map(jubjub::ExtendedPoint::from)),
            )?;

            // g_d is ensured to be large order. The relationship
            // between g_d and pk_d ultimately binds ivk to the
            // note. If this were a small order point, it would
            // not do this correctly, and the prover could
            // double-spend by finding random ivk's that satisfy
            // the relationship.
            //
            // Further, if it were small order, epk would be
            // small order too!
            g_d.assert_not_small_order(cs.namespace(|| "g_d not small order"))?;

            // Extend our note contents with the representation of
            // g_d.
            note_contents.extend(g_d.repr(cs.namespace(|| "representation of g_d"))?);

            // Booleanize our ephemeral secret key
            let esk = boolean::field_into_boolean_vec_le(cs.namespace(|| "esk"), self.esk)?;

            // Create the ephemeral public key from g_d.
            let epk = g_d.mul(cs.namespace(|| "epk computation"), &esk)?;

            // Expose epk publicly.
            epk.inputize(cs.namespace(|| "epk"))?;
        }

        // Now let's deal with pk_d. We don't do any checks and
        // essentially allow the prover to witness any 256 bits
        // they would like.
        {
            // Just grab pk_d from the witness
            let pk_d = self
                .payment_address
                .as_ref()
                .map(|e| jubjub::ExtendedPoint::from(*e.pk_d()).to_affine());

            // Witness the v-coordinate, encoded as little
            // endian bits (to match the representation)
            let v_contents = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "pk_d bits of v"),
                pk_d.map(|e| e.get_v()),
            )?;

            // Witness the sign bit
            let sign_bit = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                cs.namespace(|| "pk_d bit of u"),
                pk_d.map(|e| e.get_u().is_odd().into()),
            )?);

            // Extend the note with pk_d representation
            note_contents.extend(v_contents);
            note_contents.push(sign_bit);
        }

        assert_eq!(
            note_contents.len(),
            64 + // value
            256 + // g_d
            256 // pk_d
        );

        // Compute the hash of the note contents
        let mut cm = pedersen_hash::pedersen_hash(
            cs.namespace(|| "note content hash"),
            pedersen_hash::Personalization::NoteCommitment,
            &note_contents,
        )?;

        {
            // Booleanize the randomness
            let rcm = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "rcm"),
                self.commitment_randomness,
            )?;

            // Compute the note commitment randomness in the exponent
            let rcm = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of commitment randomness"),
                &NOTE_COMMITMENT_RANDOMNESS_GENERATOR,
                &rcm,
            )?;

            // Randomize our note commitment
            cm = cm.add(cs.namespace(|| "randomization of note commitment"), &rcm)?;
        }

        // Only the u-coordinate of the output is revealed,
        // since we know it is prime order, and we know that
        // the u-coordinate is an injective encoding for
        // elements in the prime-order subgroup.
        cm.get_u().inputize(cs.namespace(|| "commitment"))?;

        Ok(())
    }
}
```

Output电路包含的内容更少，

1. 检查`g_d`，从`esk`计算`epk`；
2. 用`value`、`g_d`和`pk_d`组装note，计算哈希获得commitment `cm`；
3. 给`cm`添加随机量`rcm`；
4. 准备公开`epk`、`cm`。

在已经解读过Sprout协议之后，我们可以发现Sapling在电路中进行证明的大体思路是类似的，但是细节上发生了很多的改变。

#### ECC

首先是椭圆曲线的使用，Sprout中Zcash只使用了哈希函数，但是Sapling引入了电路中的Jubjub曲线。不得不提的两个概念就是EdwardsPoint和MontgomeryPoint，

```rust
pub struct EdwardsPoint {
    u: AllocatedNum<bls12_381::Scalar>,
    v: AllocatedNum<bls12_381::Scalar>,
}

pub struct MontgomeryPoint {
    x: Num<bls12_381::Scalar>,
    y: Num<bls12_381::Scalar>,
}
```

完整的实现可以在[zcash/librustzcash/zcash_proofs/src/circuit/ecc.rs](https://github.com/zcash/librustzcash/blob/620ff21005017f625c4b5720561b76cb62048628/zcash_proofs/src/circuit/ecc.rs)中找到，这里只介绍它们的含义，

> Jubjub is a twisted Edwards curve of the form $-x^2 + y^2 = 1 + d x^2 y^2$ built over the BLS12-381 scalar field, with $d = -(10240/10241)$. Being a twisted Edwards curve, it has a complete addition law that avoids edge cases with doubling and identities, making it convenient to work with inside of an arithmetic circuit.

Jubjub是基于BLS12-381和上述方程的一条扭曲爱德华椭圆曲线（Twisted Edwards Curve），曲线上的点即为`EdwardsPoint`。该种曲线上的加法运算可以避免复杂的边缘情况，从而在电路中进行快速的计算。此外，每一条扭曲爱德华椭圆曲线都和另外某一条蒙哥马利曲线（Montgomery Curve）存在双向有理映射，也就是对于一个有效的`EdwardsPoint`，在对应的蒙哥马利曲线上可以转换得到一个有效的`MontgomeryPoint`。后者被用于Zcash的pedersen hash计算。

我们简单看一下`EdwardsPoint`包含的电路运算，

```rust
impl EdwardsPoint {
    pub fn get_u(&self) -> &AllocatedNum<bls12_381::Scalar> {
        &self.u
    }

    pub fn get_v(&self) -> &AllocatedNum<bls12_381::Scalar> {
        &self.v
    }

    pub fn assert_not_small_order<CS>(&self, mut cs: CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        let tmp = self.double(cs.namespace(|| "first doubling"))?;
        let tmp = tmp.double(cs.namespace(|| "second doubling"))?;
        let tmp = tmp.double(cs.namespace(|| "third doubling"))?;

        // (0, -1) is a small order point, but won't ever appear here
        // because cofactor is 2^3, and we performed three doublings.
        // (0, 1) is the neutral element, so checking if u is nonzero
        // is sufficient to prevent small order points here.
        tmp.u.assert_nonzero(cs.namespace(|| "check u != 0"))?;

        Ok(())
    }

    pub fn inputize<CS>(&self, mut cs: CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        self.u.inputize(cs.namespace(|| "u"))?;
        self.v.inputize(cs.namespace(|| "v"))?;

        Ok(())
    }

    /// This converts the point into a representation.
    pub fn repr<CS>(&self, mut cs: CS) -> Result<Vec<Boolean>, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        let mut tmp = vec![];

        let u = self.u.to_bits_le_strict(cs.namespace(|| "unpack u"))?;

        let v = self.v.to_bits_le_strict(cs.namespace(|| "unpack v"))?;

        tmp.extend(v);
        tmp.push(u[0].clone());

        Ok(tmp)
    }

    /// This 'witnesses' a point inside the constraint system.
    /// It guarantees the point is on the curve.
    pub fn witness<CS>(mut cs: CS, p: Option<jubjub::ExtendedPoint>) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        let p = p.map(|p| p.to_affine());

        // Allocate u
        let u = AllocatedNum::alloc(cs.namespace(|| "u"), || Ok(p.get()?.get_u()))?;

        // Allocate v
        let v = AllocatedNum::alloc(cs.namespace(|| "v"), || Ok(p.get()?.get_v()))?;

        Self::interpret(cs.namespace(|| "point interpretation"), &u, &v)
    }

    /// Returns `self` if condition is true, and the neutral
    /// element (0, 1) otherwise.
    pub fn conditionally_select<CS>(
        &self,
        mut cs: CS,
        condition: &Boolean,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // Compute u' = self.u if condition, and 0 otherwise
        let u_prime = AllocatedNum::alloc(cs.namespace(|| "u'"), || {
            if *condition.get_value().get()? {
                Ok(*self.u.get_value().get()?)
            } else {
                Ok(bls12_381::Scalar::zero())
            }
        })?;

        // condition * u = u'
        // if condition is 0, u' must be 0
        // if condition is 1, u' must be u
        let one = CS::one();
        cs.enforce(
            || "u' computation",
            |lc| lc + self.u.get_variable(),
            |_| condition.lc(one, bls12_381::Scalar::one()),
            |lc| lc + u_prime.get_variable(),
        );

        // Compute v' = self.v if condition, and 1 otherwise
        let v_prime = AllocatedNum::alloc(cs.namespace(|| "v'"), || {
            if *condition.get_value().get()? {
                Ok(*self.v.get_value().get()?)
            } else {
                Ok(bls12_381::Scalar::one())
            }
        })?;

        // condition * v = v' - (1 - condition)
        // if condition is 0, v' must be 1
        // if condition is 1, v' must be v
        cs.enforce(
            || "v' computation",
            |lc| lc + self.v.get_variable(),
            |_| condition.lc(one, bls12_381::Scalar::one()),
            |lc| lc + v_prime.get_variable() - &condition.not().lc(one, bls12_381::Scalar::one()),
        );

        Ok(EdwardsPoint {
            u: u_prime,
            v: v_prime,
        })
    }

    /// Performs a scalar multiplication of this twisted Edwards
    /// point by a scalar represented as a sequence of booleans
    /// in little-endian bit order.
    pub fn mul<CS>(&self, mut cs: CS, by: &[Boolean]) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // Represents the current "magnitude" of the base
        // that we're operating over. Starts at self,
        // then 2*self, then 4*self, ...
        let mut curbase = None;

        // Represents the result of the multiplication
        let mut result = None;

        for (i, bit) in by.iter().enumerate() {
            if curbase.is_none() {
                curbase = Some(self.clone());
            } else {
                // Double the previous value
                curbase = Some(
                    curbase
                        .unwrap()
                        .double(cs.namespace(|| format!("doubling {}", i)))?,
                );
            }

            // Represents the select base. If the bit for this magnitude
            // is true, this will return `curbase`. Otherwise it will
            // return the neutral element, which will have no effect on
            // the result.
            let thisbase = curbase
                .as_ref()
                .unwrap()
                .conditionally_select(cs.namespace(|| format!("selection {}", i)), bit)?;

            if result.is_none() {
                result = Some(thisbase);
            } else {
                result = Some(
                    result
                        .unwrap()
                        .add(cs.namespace(|| format!("addition {}", i)), &thisbase)?,
                );
            }
        }

        Ok(result.get()?.clone())
    }

    pub fn interpret<CS>(
        mut cs: CS,
        u: &AllocatedNum<bls12_381::Scalar>,
        v: &AllocatedNum<bls12_381::Scalar>,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // -u^2 + v^2 = 1 + du^2v^2

        let u2 = u.square(cs.namespace(|| "u^2"))?;
        let v2 = v.square(cs.namespace(|| "v^2"))?;
        let u2v2 = u2.mul(cs.namespace(|| "u^2 v^2"), &v2)?;

        let one = CS::one();
        cs.enforce(
            || "on curve check",
            |lc| lc - u2.get_variable() + v2.get_variable(),
            |lc| lc + one,
            |lc| lc + one + (EDWARDS_D, u2v2.get_variable()),
        );

        Ok(EdwardsPoint {
            u: u.clone(),
            v: v.clone(),
        })
    }

    pub fn double<CS>(&self, mut cs: CS) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // Compute T = (u + v) * (v - EDWARDS_A*u)
        //           = (u + v) * (u + v)
        let t = AllocatedNum::alloc(cs.namespace(|| "T"), || {
            let mut t0 = *self.u.get_value().get()?;
            t0.add_assign(self.v.get_value().get()?);

            let mut t1 = *self.u.get_value().get()?;
            t1.add_assign(self.v.get_value().get()?);

            t0.mul_assign(&t1);

            Ok(t0)
        })?;

        cs.enforce(
            || "T computation",
            |lc| lc + self.u.get_variable() + self.v.get_variable(),
            |lc| lc + self.u.get_variable() + self.v.get_variable(),
            |lc| lc + t.get_variable(),
        );

        // Compute A = u * v
        let a = self.u.mul(cs.namespace(|| "A computation"), &self.v)?;

        // Compute C = d*A*A
        let c = AllocatedNum::alloc(cs.namespace(|| "C"), || {
            let mut t0 = a.get_value().get()?.square();
            t0.mul_assign(EDWARDS_D);

            Ok(t0)
        })?;

        cs.enforce(
            || "C computation",
            |lc| lc + (EDWARDS_D, a.get_variable()),
            |lc| lc + a.get_variable(),
            |lc| lc + c.get_variable(),
        );

        // Compute u3 = (2.A) / (1 + C)
        let u3 = AllocatedNum::alloc(cs.namespace(|| "u3"), || {
            let mut t0 = *a.get_value().get()?;
            t0 = t0.double();

            let mut t1 = bls12_381::Scalar::one();
            t1.add_assign(c.get_value().get()?);

            let res = t1.invert().map(|t1| t0 * t1);
            if bool::from(res.is_some()) {
                Ok(res.unwrap())
            } else {
                Err(SynthesisError::DivisionByZero)
            }
        })?;

        let one = CS::one();
        cs.enforce(
            || "u3 computation",
            |lc| lc + one + c.get_variable(),
            |lc| lc + u3.get_variable(),
            |lc| lc + a.get_variable() + a.get_variable(),
        );

        // Compute v3 = (T + (EDWARDS_A-1)*A) / (1 - C)
        //            = (T - 2.A) / (1 - C)
        let v3 = AllocatedNum::alloc(cs.namespace(|| "v3"), || {
            let mut t0 = *a.get_value().get()?;
            t0 = t0.double().neg();
            t0.add_assign(t.get_value().get()?);

            let mut t1 = bls12_381::Scalar::one();
            t1.sub_assign(c.get_value().get()?);

            let res = t1.invert().map(|t1| t0 * t1);
            if bool::from(res.is_some()) {
                Ok(res.unwrap())
            } else {
                Err(SynthesisError::DivisionByZero)
            }
        })?;

        cs.enforce(
            || "v3 computation",
            |lc| lc + one - c.get_variable(),
            |lc| lc + v3.get_variable(),
            |lc| lc + t.get_variable() - a.get_variable() - a.get_variable(),
        );

        Ok(EdwardsPoint { u: u3, v: v3 })
    }

    /// Perform addition between any two points
    pub fn add<CS>(&self, mut cs: CS, other: &Self) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // Compute U = (u1 + v1) * (v2 - EDWARDS_A*u2)
        //           = (u1 + v1) * (u2 + v2)
        // (In hindsight, U was a poor choice of name.)
        let uppercase_u = AllocatedNum::alloc(cs.namespace(|| "U"), || {
            let mut t0 = *self.u.get_value().get()?;
            t0.add_assign(self.v.get_value().get()?);

            let mut t1 = *other.u.get_value().get()?;
            t1.add_assign(other.v.get_value().get()?);

            t0.mul_assign(&t1);

            Ok(t0)
        })?;

        cs.enforce(
            || "U computation",
            |lc| lc + self.u.get_variable() + self.v.get_variable(),
            |lc| lc + other.u.get_variable() + other.v.get_variable(),
            |lc| lc + uppercase_u.get_variable(),
        );

        // Compute A = v2 * u1
        let a = other.v.mul(cs.namespace(|| "A computation"), &self.u)?;

        // Compute B = u2 * v1
        let b = other.u.mul(cs.namespace(|| "B computation"), &self.v)?;

        // Compute C = d*A*B
        let c = AllocatedNum::alloc(cs.namespace(|| "C"), || {
            let mut t0 = *a.get_value().get()?;
            t0.mul_assign(b.get_value().get()?);
            t0.mul_assign(EDWARDS_D);

            Ok(t0)
        })?;

        cs.enforce(
            || "C computation",
            |lc| lc + (EDWARDS_D, a.get_variable()),
            |lc| lc + b.get_variable(),
            |lc| lc + c.get_variable(),
        );

        // Compute u3 = (A + B) / (1 + C)
        let u3 = AllocatedNum::alloc(cs.namespace(|| "u3"), || {
            let mut t0 = *a.get_value().get()?;
            t0.add_assign(b.get_value().get()?);

            let mut t1 = bls12_381::Scalar::one();
            t1.add_assign(c.get_value().get()?);

            let ret = t1.invert().map(|t1| t0 * t1);
            if bool::from(ret.is_some()) {
                Ok(ret.unwrap())
            } else {
                Err(SynthesisError::DivisionByZero)
            }
        })?;

        let one = CS::one();
        cs.enforce(
            || "u3 computation",
            |lc| lc + one + c.get_variable(),
            |lc| lc + u3.get_variable(),
            |lc| lc + a.get_variable() + b.get_variable(),
        );

        // Compute v3 = (U - A - B) / (1 - C)
        let v3 = AllocatedNum::alloc(cs.namespace(|| "v3"), || {
            let mut t0 = *uppercase_u.get_value().get()?;
            t0.sub_assign(a.get_value().get()?);
            t0.sub_assign(b.get_value().get()?);

            let mut t1 = bls12_381::Scalar::one();
            t1.sub_assign(c.get_value().get()?);

            let ret = t1.invert().map(|t1| t0 * t1);
            if bool::from(ret.is_some()) {
                Ok(ret.unwrap())
            } else {
                Err(SynthesisError::DivisionByZero)
            }
        })?;

        cs.enforce(
            || "v3 computation",
            |lc| lc + one - c.get_variable(),
            |lc| lc + v3.get_variable(),
            |lc| lc + uppercase_u.get_variable() - a.get_variable() - b.get_variable(),
        );

        Ok(EdwardsPoint { u: u3, v: v3 })
    }
}
```

然后是曲线上的计算[`ecc::fixed_base_multiplication`](https://github.com/zcash/librustzcash/blob/620ff21005017f625c4b5720561b76cb62048628/zcash_proofs/src/circuit/ecc.rs#L27)，

```rust
/// Perform a fixed-base scalar multiplication with
/// `by` being in little-endian bit order.
pub fn fixed_base_multiplication<CS>(
    mut cs: CS,
    base: FixedGenerator,
    by: &[Boolean],
) -> Result<EdwardsPoint, SynthesisError>
where
    CS: ConstraintSystem<bls12_381::Scalar>,
{
    // Represents the result of the multiplication
    let mut result = None;

    // 将by切成3个子数组，用不同的window计算后再合并
    for (i, (chunk, window)) in by.chunks(3).zip(base.iter()).enumerate() {
        let chunk_a = chunk
            .get(0)
            .cloned()
            .unwrap_or_else(|| Boolean::constant(false));
        let chunk_b = chunk
            .get(1)
            .cloned()
            .unwrap_or_else(|| Boolean::constant(false));
        let chunk_c = chunk
            .get(2)
            .cloned()
            .unwrap_or_else(|| Boolean::constant(false));

        // TODO: rename to lookup3_uv
        let (u, v) = lookup3_xy(
            cs.namespace(|| format!("window table lookup {}", i)),
            &[chunk_a, chunk_b, chunk_c],
            window,
        )?;

        // 临时结果p
        let p = EdwardsPoint { u, v };

        if result.is_none() {
            result = Some(p);
        } else {
            result = Some(
                result
                    .unwrap()
                    .add(cs.namespace(|| format!("addition {}", i)), &p)?,
            );
        }
    }

    Ok(result.get()?.clone())
}
```

关于[`FixedGenerator`](https://github.com/zcash/librustzcash/blob/3b283ca4451d4f1eeae8f7ceff1c659a01db8efe/zcash_proofs/src/constants.rs#L70)，它来源于某个固定生成元`gen`，不论形式为`SubgroupPoint`还是`ExtendedPoint`，都包含`u`、`v`两个坐标值，

```rust
/// Creates the 3-bit window table `[0, 1, ..., 8]` for different magnitudes of a fixed
/// generator.
pub fn generate_circuit_generator(mut gen: jubjub::SubgroupPoint) -> FixedGeneratorOwned {
    let mut windows = vec![];

    // const FIXED_BASE_CHUNKS_PER_GENERATOR: usize = 84;
    for _ in 0..FIXED_BASE_CHUNKS_PER_GENERATOR {
        let mut coeffs = vec![(Scalar::zero(), Scalar::one())];
        let mut g = gen;
        for _ in 0..7 {
            let g_affine = jubjub::ExtendedPoint::from(g).to_affine();
            coeffs.push((g_affine.get_u(), g_affine.get_v()));
            g += gen;
        }
        windows.push(coeffs);

        // gen = gen * 8
        gen = g;
    }

    windows
}
```

此外这里还用到了[`lookup3_xy`](https://github.com/zkcrypto/bellman/blob/4c1746c9c22f3537a86e5320b4fd6c2354291616/src/gadgets/lookup.rs#L31)，

```rust
/// Performs a 3-bit window table lookup. `bits` is in
/// little-endian order.
pub fn lookup3_xy<Scalar: PrimeField, CS>(
    mut cs: CS,
    bits: &[Boolean],
    coords: &[(Scalar, Scalar)],
) -> Result<(AllocatedNum<Scalar>, AllocatedNum<Scalar>), SynthesisError>
where
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(bits.len(), 3);
    assert_eq!(coords.len(), 8);

    // Calculate the index into `coords`
    let i = match (
        bits[0].get_value(),
        bits[1].get_value(),
        bits[2].get_value(),
    ) {
        (Some(a_value), Some(b_value), Some(c_value)) => {
            let mut tmp = 0;
            if a_value {
                tmp += 1;
            }
            if b_value {
                tmp += 2;
            }
            if c_value {
                tmp += 4;
            }
            Some(tmp)
        }
        _ => None,
    };

    // Allocate the x-coordinate resulting from the lookup
    let res_x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(coords[*i.get()?].0))?;

    // Allocate the y-coordinate resulting from the lookup
    let res_y = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(coords[*i.get()?].1))?;

    // Compute the coefficients for the lookup constraints
    let mut x_coeffs = [Scalar::zero(); 8];
    let mut y_coeffs = [Scalar::zero(); 8];
    synth::<Scalar, _>(3, coords.iter().map(|c| &c.0), &mut x_coeffs);
    synth::<Scalar, _>(3, coords.iter().map(|c| &c.1), &mut y_coeffs);

    let precomp = Boolean::and(cs.namespace(|| "precomp"), &bits[1], &bits[2])?;

    let one = CS::one();

    cs.enforce(
        || "x-coordinate lookup",
        |lc| {
            lc + (x_coeffs[0b001], one)
                + &bits[1].lc::<Scalar>(one, x_coeffs[0b011])
                + &bits[2].lc::<Scalar>(one, x_coeffs[0b101])
                + &precomp.lc::<Scalar>(one, x_coeffs[0b111])
        },
        |lc| lc + &bits[0].lc::<Scalar>(one, Scalar::one()),
        |lc| {
            lc + res_x.get_variable()
                - (x_coeffs[0b000], one)
                - &bits[1].lc::<Scalar>(one, x_coeffs[0b010])
                - &bits[2].lc::<Scalar>(one, x_coeffs[0b100])
                - &precomp.lc::<Scalar>(one, x_coeffs[0b110])
        },
    );

    cs.enforce(
        || "y-coordinate lookup",
        |lc| {
            lc + (y_coeffs[0b001], one)
                + &bits[1].lc::<Scalar>(one, y_coeffs[0b011])
                + &bits[2].lc::<Scalar>(one, y_coeffs[0b101])
                + &precomp.lc::<Scalar>(one, y_coeffs[0b111])
        },
        |lc| lc + &bits[0].lc::<Scalar>(one, Scalar::one()),
        |lc| {
            lc + res_y.get_variable()
                - (y_coeffs[0b000], one)
                - &bits[1].lc::<Scalar>(one, y_coeffs[0b010])
                - &bits[2].lc::<Scalar>(one, y_coeffs[0b100])
                - &precomp.lc::<Scalar>(one, y_coeffs[0b110])
        },
    );

    Ok((res_x, res_y))
}
```

#### Pedersen Hash

#### Blake2s

### Bellman计算

Sapling后面调用bellman生成证明时，同样使用了`create_random_proof`，因此过程和之前一样，以及使用了相同的`ProvingAssignment`，不再赘述。
