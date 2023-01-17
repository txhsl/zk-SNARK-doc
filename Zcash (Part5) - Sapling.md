# Zcash Part5

## Sapling

看完了Sprout，我们来看Sapling，这个协议只对每一个input和output生成分别的证明。在上一节中我们知道，Sprout协议处理复杂交易时JoinSplit要完成零钱Note的反复铸造和销毁，毫无疑问在性能上有很大的提升空间。

针对Sprout协议存在的性能短板，Zcash提出了作为改进的Sapling协议。在之前的内容中，我们已经知道Sapling是在Sprout基础上重建的协议，甚至地址上可以相互兼容，因此它们的相似程度也非常高。

### zcash入口

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

以上是对input的证明入口，这里接收数据后做一些验证，用`ask`、`nsk`生成了证明生成密钥，然后向外部调用，将返回的证明写入`zkproof`返回，同时返回的还有公开参数`cv`和`rk`。

这里没有Sprout一样的参数检测和说明，简单介绍一下使用的参数，可以回看Part1，

1. expanded spending key中的`ask`、`nsk`，`ask`这里写作了`ak`；
3. note中的`d`、`rcm`和`v`，`v`这里写作了`value`；
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

### librustzcash中转

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

以上方法发挥和Sprout中`create_proof`类似的作用，准备好Groth16需要的电路和参数，收到证明后处理nullifier和value commitment。

我们还记得Sprout中JoinSplit电路的公开参数包括anchor root、`h_sig`、nullifier、`mac`、commitment以及`vpub_old`和`vpub_new`。而这里Spend电路的公开参数则是anchor root、`rk`、nullifier和commitment。

比较重要的一点是`self.cv_sum += value_commitment;`，**我们看到commitment被用于value的平衡验证，这一点不再是通过证明完成**。以及`let rcv = jubjub::Fr::random(&mut rng);`，这个随机元被用于混淆保护`value`的值不被推测。`ValueCommitment`的[定义](https://github.com/zcash/librustzcash/blob/23922ca290e300db3252e484dfdcd18c17ed75ee/zcash_primitives/src/sapling/value.rs#L107)如下，

```rust
#[derive(Clone, Debug)]
pub struct ValueCommitment(jubjub::ExtendedPoint);

impl ValueCommitment {
    /// Derives a `ValueCommitment` by $\mathsf{ValueCommit^{Sapling}}$.
    ///
    /// Defined in [Zcash Protocol Spec § 5.4.8.3: Homomorphic Pedersen commitments (Sapling and Orchard)][concretehomomorphiccommit].
    ///
    /// [concretehomomorphiccommit]: https://zips.z.cash/protocol/protocol.pdf#concretehomomorphiccommit
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

当然`output_proof`也出现在相同的位置，依然关注`bsk`和`cv_sum`，后面会用到，

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

#### 证明电路

这里同样的，我们可以在[zcash/librustzcash/zcash_proofs/src/circuit/sapling.rs](https://github.com/zcash/librustzcash/blob/main/zcash_proofs/src/circuit/sapling.rs#L118)找到Spend电路的定义，对应代码如下，

```rust
impl Circuit<bls12_381::Scalar> for Spend {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Prover witnesses ak (ensures that it's on the curve)
        let ak = ecc::EdwardsPoint::witness(
            cs.namespace(|| "ak"),
            self.proof_generation_key.as_ref().map(|k| k.ak.into()),
        )?;

        // There are no sensible attacks on small order points
        // of ak (that we're aware of!) but it's a cheap check,
        // so we do it.
        ak.assert_not_small_order(cs.namespace(|| "ak not small order"))?;

        // Rerandomize ak and expose it as an input to the circuit
        {
            let ar = boolean::field_into_boolean_vec_le(cs.namespace(|| "ar"), self.ar)?;

            // Compute the randomness in the exponent
            let ar = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of randomization for the signing key"),
                &SPENDING_KEY_GENERATOR,
                &ar,
            )?;

            let rk = ak.add(cs.namespace(|| "computation of rk"), &ar)?;

            rk.inputize(cs.namespace(|| "rk"))?;
        }

        // Compute nk = [nsk] ProofGenerationKey
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
        ivk.truncate(jubjub::Fr::CAPACITY as usize);

        // Witness g_d, checking that it's on the curve.
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
        let pk_d = g_d.mul(cs.namespace(|| "compute pk_d"), &ivk)?;

        // Compute note contents:
        // value (in big endian) followed by g_d and pk_d
        let mut note_contents = vec![];

        // Handle the value; we'll need it later for the
        // dummy input check.
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
        let mut cm = pedersen_hash::pedersen_hash(
            cs.namespace(|| "note content hash"),
            pedersen_hash::Personalization::NoteCommitment,
            &note_contents,
        )?;

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
            cur = pedersen_hash::pedersen_hash(
                cs.namespace(|| "computation of pedersen hash"),
                pedersen_hash::Personalization::MerkleTree(i),
                &preimage,
            )?
            .get_u()
            .clone(); // Injective encoding
        }

        {
            let real_anchor_value = self.anchor;

            // Allocate the "real" anchor that will be exposed.
            let rt = num::AllocatedNum::alloc(cs.namespace(|| "conditional anchor"), || {
                Ok(*real_anchor_value.get()?)
            })?;

            // (cur - rt) * value = 0
            // if value is zero, cur and rt can be different
            // if value is nonzero, they must be equal
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

1. 检查ak，计算rk、nk、ivk、pkd等密钥；
2. 
3. 
4. 

具体细节可以浏览注释。同一文件中，我们还可以找到Sapling使用的Output电路，

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

### bellman计算

Sapling后面调用bellman生成证明时，同样使用了`create_random_proof`，因此过程和之前一样，以及使用了相同的`ProvingAssignment`，不再赘述。
