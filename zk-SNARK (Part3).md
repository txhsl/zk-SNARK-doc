# zk-SNARK (Part3)

接上文，我们已经介绍了Groth16的定义，包括参数的预设、证明的生成、验证，以及复现论据的模拟过程。接下来，我们先从Zcash的Sprout和Sapling协议入手，看一看Zcash如何实现zk-SNARK。

Zcash中的zk-SNARK总是证明两件事：

1. Prover销毁了某个属于自己的Note；
2. Prover铸造了某个有效的Note给目标地址。

## Sprout证明

### zcash入口

先上JoinSplit的证明入口，在[zcash/zcash/src/zcash/JoinSplit.cpp](https://github.com/zcash/zcash/blob/master/src/zcash/JoinSplit.cpp)，该入口接收来自Zcash其他模块的结构输入，每个JoinSplit都包含2个input和2个output，分别有一个或者两个可为空，同时包含一个vpub_old和vpub_new，分别可都为零。需要注意的是`input.value`和`output.value`代表Sprout隐匿资产池的销毁和铸造数量，而`vpub_old`和`vpub_new`代表公开资产池的销毁和铸造数量，别担心，我们会在平衡验证的描述中具体解释。

```cpp
template<size_t NumInputs, size_t NumOutputs>
SproutProof JoinSplit<NumInputs, NumOutputs>::prove(
    const std::array<JSInput, NumInputs>& inputs,
    const std::array<JSOutput, NumOutputs>& outputs,
    std::array<SproutNote, NumOutputs>& out_notes,
    std::array<ZCNoteEncryption::Ciphertext, NumOutputs>& out_ciphertexts,
    uint256& out_ephemeralKey,
    const Ed25519VerificationKey& joinSplitPubKey,
    uint256& out_randomSeed,
    std::array<uint256, NumInputs>& out_macs,
    std::array<uint256, NumInputs>& out_nullifiers,
    std::array<uint256, NumOutputs>& out_commitments,
    uint64_t vpub_old,
    uint64_t vpub_new,
    const uint256& rt,
    bool computeProof,
    uint256 *out_esk // Payment disclosure
) {
    if (vpub_old > MAX_MONEY) {
        throw std::invalid_argument("nonsensical vpub_old value");
    }

    if (vpub_new > MAX_MONEY) {
        throw std::invalid_argument("nonsensical vpub_new value");
    }

    uint64_t lhs_value = vpub_old;
    uint64_t rhs_value = vpub_new;

    for (size_t i = 0; i < NumInputs; i++) {
        // Sanity checks of input
        {
            // If note has nonzero value
            if (inputs[i].note.value() != 0) {
                // The witness root must equal the input root.
                if (inputs[i].witness.root() != rt) {
                    throw std::invalid_argument("joinsplit not anchored to the correct root");
                }

                // The tree must witness the correct element
                if (inputs[i].note.cm() != inputs[i].witness.element()) {
                    throw std::invalid_argument("witness of wrong element for joinsplit input");
                }
            }

            // Ensure we have the key to this note.
            if (inputs[i].note.a_pk != inputs[i].key.address().a_pk) {
                throw std::invalid_argument("input note not authorized to spend with given key");
            }

            // Balance must be sensical
            if (inputs[i].note.value() > MAX_MONEY) {
                throw std::invalid_argument("nonsensical input note value");
            }

            lhs_value += inputs[i].note.value();

            if (lhs_value > MAX_MONEY) {
                throw std::invalid_argument("nonsensical left hand size of joinsplit balance");
            }
        }

        // Compute nullifier of input
        out_nullifiers[i] = inputs[i].nullifier();
    }

    // Sample randomSeed
    out_randomSeed = random_uint256();

    // Compute h_sig
    uint256 h_sig = JoinSplit<NumInputs, NumOutputs>::h_sig(
        out_randomSeed, out_nullifiers, joinSplitPubKey);

    // Sample phi
    uint252 phi = random_uint252();

    // Compute notes for outputs
    for (size_t i = 0; i < NumOutputs; i++) {
        // Sanity checks of output
        {
            if (outputs[i].value > MAX_MONEY) {
                throw std::invalid_argument("nonsensical output value");
            }

            rhs_value += outputs[i].value;

            if (rhs_value > MAX_MONEY) {
                throw std::invalid_argument("nonsensical right hand side of joinsplit balance");
            }
        }

        // Sample r
        uint256 r = random_uint256();

        out_notes[i] = outputs[i].note(phi, r, i, h_sig);
    }

    if (lhs_value != rhs_value) {
        throw std::invalid_argument("invalid joinsplit balance");
    }

    // Compute the output commitments
    for (size_t i = 0; i < NumOutputs; i++) {
        out_commitments[i] = out_notes[i].cm();
    }

    // Encrypt the ciphertexts containing the note
    // plaintexts to the recipients of the value.
    {
        ZCNoteEncryption encryptor(h_sig);

        for (size_t i = 0; i < NumOutputs; i++) {
            SproutNotePlaintext pt(out_notes[i], outputs[i].memo);

            out_ciphertexts[i] = pt.encrypt(encryptor, outputs[i].addr.pk_enc);
        }

        out_ephemeralKey = encryptor.get_epk();

        // !!! Payment disclosure START
        if (out_esk != nullptr) {
            *out_esk = encryptor.get_esk();
        }
        // !!! Payment disclosure END
    }

    // Authenticate h_sig with each of the input
    // spending keys, producing macs which protect
    // against malleability.
    for (size_t i = 0; i < NumInputs; i++) {
        out_macs[i] = PRF_pk(inputs[i].key, i, h_sig);
    }

    if (!computeProof) {
        return GrothProof();
    }

    GrothProof proof;

    CDataStream ss1(SER_NETWORK, PROTOCOL_VERSION);
    ss1 << inputs[0].witness.path();
    std::vector<unsigned char> auth1(ss1.begin(), ss1.end());

    CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
    ss2 << inputs[1].witness.path();
    std::vector<unsigned char> auth2(ss2.begin(), ss2.end());

    librustzcash_sprout_prove(
        proof.begin(),

        phi.begin(),
        rt.begin(),
        h_sig.begin(),

        inputs[0].key.begin(),
        inputs[0].note.value(),
        inputs[0].note.rho.begin(),
        inputs[0].note.r.begin(),
        auth1.data(),

        inputs[1].key.begin(),
        inputs[1].note.value(),
        inputs[1].note.rho.begin(),
        inputs[1].note.r.begin(),
        auth2.data(),

        out_notes[0].a_pk.begin(),
        out_notes[0].value(),
        out_notes[0].r.begin(),

        out_notes[1].a_pk.begin(),
        out_notes[1].value(),
        out_notes[1].r.begin(),

        vpub_old,
        vpub_new
    );

    return proof;
}
```

在解包上述输入后，方法先在本地采样rng执行输入数据的合法性验证和JoinSplit的计算组装，最后调用librustzcash生成证明，期望生成的是Groth16证明（现版本已经不使用最初的BCTV14）。具体来说，

1. 检测交易的输入和输出总数量都合法；
2. 检测每个input note，**witness来自的merkle tree root等于输入参数里交易声明的tree root**，witness产生时merkle tree最新的`element`等于note可计算出的`commitment`，发送者spending key衍生出的`a_pk`是note铸造给的`a_pk`，note标称的`value`是合法的；
3. 总和交易中所有的input value，总价是合法的，`lhs_value = vpub_old + inputs[0].note.value() + inputs[1].note.value()`，`lhs_value`代表了发送者销毁的公开资金和隐匿资金总量；
4. 给每一个input note计算`nullifier`；
5. 取随机的`randomSeed`计算`h_sig`，再取`phi`、`r`为每个output计算新note；
6. 检测每个output note，note标称的`value`是合法的；
7. 总和所有的output value，总价是合法的，`rhs_value = vpub_new + outputs[0].note.value() + outputs[1].note.value()`，`rhs_value`代表了发送者铸造的公开资金和隐匿资金总量；
8. 给每一个output note计算`commitment`；
9. 加密每一个output note，之后通过secret sharing传递给接收者；
10. 用`h_sig`给每个input note添加保护，防止被盗用；
11. 提取每个input note的witness的sprout merkle tree path，这个路径是commitment树的一条subtree（也就是包含所有的父节点和主路径上的兄弟节点）；
12. 调用librustzcash生成Groth16证明，传入的参数有，
    - 交易使用的sprout merkle tree root，生成的`phi`、`h_sig`；
    - 消耗每个input所需的spending key；
    - 每个input note的关键参数`v`、`rho`、`r`；
    - 每个note的witness的sprout merkle tree path；
    - 生成的每个output note的`a_pk`、`v`、`r`。

### librustzcash中转

#### 参数准备

zcash/zcash中的`librustzcash_sprout_prove`实际引用到了[zcash/librustzcash/zcash_proofs/src/sprout.rs](https://github.com/zcash/librustzcash/blob/main/zcash_proofs/src/sprout.rs)，对应以下内容，

```rust
/// Sprout JoinSplit proof generation.
#[allow(clippy::too_many_arguments)]
pub fn create_proof(
    phi: [u8; 32],
    rt: [u8; 32],
    h_sig: [u8; 32],

    // First input
    in_sk1: [u8; 32],
    in_value1: u64,
    in_rho1: [u8; 32],
    in_r1: [u8; 32],
    in_auth1: &[u8; WITNESS_PATH_SIZE],

    // Second input
    in_sk2: [u8; 32],
    in_value2: u64,
    in_rho2: [u8; 32],
    in_r2: [u8; 32],
    in_auth2: &[u8; WITNESS_PATH_SIZE],

    // First output
    out_pk1: [u8; 32],
    out_value1: u64,
    out_r1: [u8; 32],

    // Second output
    out_pk2: [u8; 32],
    out_value2: u64,
    out_r2: [u8; 32],

    // Public value
    vpub_old: u64,
    vpub_new: u64,

    proving_key: &Parameters<Bls12>,
) -> Proof<Bls12> {
    let mut inputs = Vec::with_capacity(2);
    {
        let mut handle_input = |sk, value, rho, r, mut auth: &[u8]| {
            let value = Some(value);
            let rho = Some(UniqueRandomness(rho));
            let r = Some(CommitmentRandomness(r));
            let a_sk = Some(SpendingKey(sk));

            // skip the first byte
            assert_eq!(auth[0], TREE_DEPTH as u8);
            auth = &auth[1..];

            // merkle tree path
            let mut auth_path = [None; TREE_DEPTH];
            for i in (0..TREE_DEPTH).rev() {
                // skip length of inner vector
                assert_eq!(auth[0], 32);
                auth = &auth[1..];

                let mut sibling = [0u8; 32];
                sibling.copy_from_slice(&auth[0..32]);
                auth = &auth[32..];

                auth_path[i] = Some((sibling, false));
            }

            // position
            let mut position = {
                let mut bytes = [0; 8];
                bytes.copy_from_slice(&auth[0..8]);
                u64::from_le_bytes(bytes)
            };

            for entry in auth_path.iter_mut() {
                if let Some(p) = entry {
                    p.1 = (position & 1) == 1;
                }

                position >>= 1;
            }

            inputs.push(JsInput {
                value,
                a_sk,
                rho,
                r,
                auth_path,
            });
        };

        handle_input(in_sk1, in_value1, in_rho1, in_r1, &in_auth1[..]);
        handle_input(in_sk2, in_value2, in_rho2, in_r2, &in_auth2[..]);
    }

    let mut outputs = Vec::with_capacity(2);
    {
        let mut handle_output = |a_pk, value, r| {
            outputs.push(JsOutput {
                value: Some(value),
                a_pk: Some(PayingKey(a_pk)),
                r: Some(CommitmentRandomness(r)),
            });
        };

        handle_output(out_pk1, out_value1, out_r1);
        handle_output(out_pk2, out_value2, out_r2);
    }

    let js = JoinSplit {
        vpub_old: Some(vpub_old),
        vpub_new: Some(vpub_new),
        h_sig: Some(h_sig),
        phi: Some(phi),
        inputs,
        outputs,
        rt: Some(rt),
    };

    // Initialize secure RNG
    let mut rng = OsRng;

    create_random_proof(js, proving_key, &mut rng).expect("proving should not fail")
}
```

以上方法接收纯粹的数值输入，然后重新解析为类型和数组，并且根据输入的密钥准备好Groth16要求的电路和参数，具体来说，

1. 接受来自`JoinSplit<NumInputs, NumOutputs>::prove`的所有交易参数，以及附带的、来自Zcash的Sprout JoinSplit的公用参数；
2. 对每一个input，解析`v`、`rho`、`r`、spending key，还原commitment的merkle tree path，注意是从leaf到root的倒序，最后组装成数组；
3. 对每一个output，解析`v`、`a_pk`、`r`，组装成数组；
4. 解析其他参数并重新构建JoinSplit；
5. 采样一次rng然后调用`create_random_proof`。

这里在执行`let js = JoinSplit {...};`这一行代码时，顺便也携带了JoinSplit对应的电路。

#### 证明电路

这个电路的定义在[zcash/librustzcash/zcash_proofs/src/circuit/sprout/mod.rs](https://github.com/zcash/librustzcash/blob/main/zcash_proofs/src/circuit/sprout/mod.rs#L57)，对应下面的代码，

```rust
impl<Scalar: PrimeField> Circuit<Scalar> for JoinSplit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        assert_eq!(self.inputs.len(), 2);
        assert_eq!(self.outputs.len(), 2);

        // vpub_old is the value entering the
        // JoinSplit from the "outside" value
        // pool
        let vpub_old = NoteValue::new(cs.namespace(|| "vpub_old"), self.vpub_old)?;

        // vpub_new is the value leaving the
        // JoinSplit into the "outside" value
        // pool
        let vpub_new = NoteValue::new(cs.namespace(|| "vpub_new"), self.vpub_new)?;

        // The left hand side of the balance equation
        // vpub_old + inputs[0].value + inputs[1].value
        let mut lhs = vpub_old.lc();

        // The right hand side of the balance equation
        // vpub_old + inputs[0].value + inputs[1].value
        let mut rhs = vpub_new.lc();

        // Witness rt (merkle tree root)
        let rt = witness_u256(cs.namespace(|| "rt"), self.rt.as_ref().map(|v| &v[..]))?;

        // Witness h_sig
        let h_sig = witness_u256(
            cs.namespace(|| "h_sig"),
            self.h_sig.as_ref().map(|v| &v[..]),
        )
        .unwrap();

        // Witness phi
        let phi = witness_u252(cs.namespace(|| "phi"), self.phi.as_ref().map(|v| &v[..]))?;

        let mut input_notes = vec![];
        let mut lhs_total = self.vpub_old;

        // Iterate over the JoinSplit inputs
        for (i, input) in self.inputs.into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("input {}", i));

            // Accumulate the value of the left hand side
            if let Some(value) = input.value {
                lhs_total = lhs_total.map(|v| v.wrapping_add(value));
            }

            // Allocate the value of the note
            let value = NoteValue::new(cs.namespace(|| "value"), input.value)?;

            // Compute the nonce (for PRF inputs) which is false
            // for the first input, and true for the second input.
            let nonce = match i {
                0 => false,
                1 => true,
                _ => unreachable!(),
            };

            // Perform input note computations
            input_notes.push(InputNote::compute(
                cs.namespace(|| "note"),
                input.a_sk,
                input.rho,
                input.r,
                &value,
                &h_sig,
                nonce,
                input.auth_path,
                &rt,
            )?);

            // Add the note value to the left hand side of
            // the balance equation
            lhs = lhs + &value.lc();
        }

        // Rebind lhs so that it isn't mutable anymore
        let lhs = lhs;

        // See zcash/zcash/issues/854
        {
            // Expected sum of the left hand side of the balance
            // equation, expressed as a 64-bit unsigned integer
            let lhs_total =
                NoteValue::new(cs.namespace(|| "total value of left hand side"), lhs_total)?;

            // Enforce that the left hand side can be expressed as a 64-bit
            // integer
            cs.enforce(
                || "left hand side can be expressed as a 64-bit unsigned integer",
                |_| lhs.clone(),
                |lc| lc + CS::one(),
                |_| lhs_total.lc(),
            );
        }

        let mut output_notes = vec![];

        // Iterate over the JoinSplit outputs
        for (i, output) in self.outputs.into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("output {}", i));

            let value = NoteValue::new(cs.namespace(|| "value"), output.value)?;

            // Compute the nonce (for PRF inputs) which is false
            // for the first output, and true for the second output.
            let nonce = match i {
                0 => false,
                1 => true,
                _ => unreachable!(),
            };

            // Perform output note computations
            output_notes.push(OutputNote::compute(
                cs.namespace(|| "note"),
                output.a_pk,
                &value,
                output.r,
                &phi,
                &h_sig,
                nonce,
            )?);

            // Add the note value to the right hand side of
            // the balance equation
            rhs = rhs + &value.lc();
        }

        // Enforce that balance is equal
        cs.enforce(
            || "balance equation",
            |_| lhs.clone(),
            |lc| lc + CS::one(),
            |_| rhs,
        );

        let mut public_inputs = vec![];
        public_inputs.extend(rt);
        public_inputs.extend(h_sig);

        for note in input_notes {
            public_inputs.extend(note.nf);
            public_inputs.extend(note.mac);
        }

        for note in output_notes {
            public_inputs.extend(note.cm);
        }

        public_inputs.extend(vpub_old.bits_le());
        public_inputs.extend(vpub_new.bits_le());

        pack_into_inputs(cs.namespace(|| "input packing"), &public_inputs)
    }
}
```

以上代码按照顺序包含了以下操作：

1. 验证input和output的数量都为2；
2. 见证`vpub_old`、`vpub_new`、merkle tree root `rt`、`h_sig`和`phi`，使用到了新结构[`NoteValue`](https://github.com/zcash/librustzcash/blob/main/zcash_proofs/src/circuit/sprout/mod.rs#L220)和方法[`witness_u256`](https://github.com/zcash/librustzcash/blob/main/zcash_proofs/src/circuit/sprout/mod.rs#L320)；

```rust
pub struct NoteValue {
    value: Option<u64>,
    // Least significant digit first
    bits: Vec<AllocatedBit>,
}

impl NoteValue {
    fn new<Scalar, CS>(mut cs: CS, value: Option<u64>) -> Result<NoteValue, SynthesisError>
    where
        Scalar: PrimeField,
        CS: ConstraintSystem<Scalar>,
    {
        let mut values;
        match value {
            Some(mut val) => {
                values = vec![];
                for _ in 0..64 {
                    values.push(Some(val & 1 == 1));
                    val >>= 1;
                }
            }
            None => {
                values = vec![None; 64];
            }
        }

        let mut bits = vec![];
        for (i, value) in values.into_iter().enumerate() {
            bits.push(AllocatedBit::alloc(
                cs.namespace(|| format!("bit {}", i)),
                value,
            )?);
        }

        Ok(NoteValue { value, bits })
    }

    /// Encodes the bits of the value into little-endian
    /// byte order.
    fn bits_le(&self) -> Vec<Boolean> {
        self.bits
            .chunks(8)
            .flat_map(|v| v.iter().rev())
            .cloned()
            .map(Boolean::from)
            .collect()
    }

    /// Computes this value as a linear combination of
    /// its bits.
    fn lc<Scalar: PrimeField>(&self) -> LinearCombination<Scalar> {
        let mut tmp = LinearCombination::zero();

        let mut coeff = Scalar::one();
        for b in &self.bits {
            tmp = tmp + (coeff, b.get_variable());
            coeff = coeff.double();
        }

        tmp
    }

    fn get_value(&self) -> Option<u64> {
        self.value
    }
}
```

首先是结构`NoteValue`，它包含了一个`value`的原始数值和一个见证后的`bits`数组，用两种格式表示相同的内容。在调用初始化时，上述代码会将传入的`u64`类型逐步减位，转换成由0和1表示的数组。拆解完成后，该输出会被`AllocatedBit`电路见证，然后存储到`bits`数组中。关于`AllocatedBit`，我们会在之后的哈希电路中再次见到它并具体描述。

在`JoinSplit`、`InputNote`和`OutputNote`的计算中，代码均使用`value.lc()`作为输入，而非`value.value`。`lc`方法逆方向将`bits`组建为`LinearCombination<Scalar>`。由于只在`Scalar::one()`上做正数乘法和正数加法，该方法必然返回一个正值。

```rust
/// Witnesses some bytes in the constraint system,
/// skipping the first `skip_bits`.
fn witness_bits<Scalar, CS>(
    mut cs: CS,
    value: Option<&[u8]>,
    num_bits: usize,
    skip_bits: usize,
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let bit_values = if let Some(value) = value {
        let mut tmp = vec![];
        for b in value
            .iter()
            .flat_map(|&m| (0..8).rev().map(move |i| m >> i & 1 == 1))
            .skip(skip_bits)
        {
            tmp.push(Some(b));
        }
        tmp
    } else {
        vec![None; num_bits]
    };
    assert_eq!(bit_values.len(), num_bits);

    let mut bits = vec![];

    for (i, value) in bit_values.into_iter().enumerate() {
        bits.push(Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| format!("bit {}", i)),
            value,
        )?));
    }

    Ok(bits)
}

fn witness_u256<Scalar, CS>(cs: CS, value: Option<&[u8]>) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    witness_bits(cs, value, 256, 0)
}
```

而`witness_u256`方法，则接受`u8`类型作为输入，以类似的过程将`value`转换为长度为256的`bits`数组。在方法中，我们可以看到代码同样调用了`AllocatedBit`进行见证。

3. 遍历JoinSplit的每个input，统计并见证它们的`value`；
4. 为inputs[0]和inputs[1]授予不同的`nonce`(false和true)；
5. 组装包含`nonce`的input notes并见证（这里包含一个嵌套，在下面）；
6. enforce验证统计的input value总和等于`vpub_old`，`lhs * 1 = lhs_total`，需要注意的是，`lhs = vpub_old.lc() + inputs[0].value.lc() + inputs[1].value.lc()`，而`lhs_total = vpub_old + inputs[0].value + inputs[1].value`。若该验证不通过，则存在某个input的`value`非法；
7. 遍历JoinSplit的每个output，统计并见证它们的`value`；
8. 为outputs[0]和outputs[1]授予不同的`nonce`(false和true)；
8. 组装包含`nonce`的output notes并见证（这里包含一个嵌套，在下面），组装时使用`value.bits`，故必为正数；
9. enforce验证统计的input value总和output value总和相等，`lhs * 1 = rhs`，需要注意的是，`rhs = vpub_new.lc() + outputs[0].value.lc() + outputs[1].value.lc()`，其中每一项都必为正数，且`output.value`必然和上一步生成Note的value相同；
10. 将`rt`、`h_sig`、`nf`、`mac`、`cm`、`vpub_old`、`vpub_new`打包为public inputs。

在第4步声明中，又嵌套了另一个电路[InputNote](https://github.com/zcash/librustzcash/blob/main/zcash_proofs/src/circuit/sprout/input.rs)计算note的mac和nf，也做了一些进一步的验证，

```rust
impl InputNote {
    #[allow(clippy::too_many_arguments)]
    pub fn compute<Scalar, CS>(
        mut cs: CS,
        a_sk: Option<SpendingKey>,
        rho: Option<UniqueRandomness>,
        r: Option<CommitmentRandomness>,
        value: &NoteValue,
        h_sig: &[Boolean],
        nonce: bool,
        auth_path: [Option<([u8; 32], bool)>; TREE_DEPTH],
        rt: &[Boolean],
    ) -> Result<InputNote, SynthesisError>
    where
        Scalar: PrimeField,
        CS: ConstraintSystem<Scalar>,
    {
        let a_sk = witness_u252(
            cs.namespace(|| "a_sk"),
            a_sk.as_ref().map(|a_sk| &a_sk.0[..]),
        )?;

        let rho = witness_u256(cs.namespace(|| "rho"), rho.as_ref().map(|rho| &rho.0[..]))?;

        let r = witness_u256(cs.namespace(|| "r"), r.as_ref().map(|r| &r.0[..]))?;

        let a_pk = prf_a_pk(cs.namespace(|| "a_pk computation"), &a_sk)?;

        let nf = prf_nf(cs.namespace(|| "nf computation"), &a_sk, &rho)?;

        let mac = prf_pk(cs.namespace(|| "mac computation"), &a_sk, h_sig, nonce)?;

        let cm = note_comm(
            cs.namespace(|| "cm computation"),
            &a_pk,
            &value.bits_le(),
            &rho,
            &r,
        )?;

        // Witness into the merkle tree
        let mut cur = cm;

        for (i, layer) in auth_path.iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("layer {}", i));

            let cur_is_right = AllocatedBit::alloc(
                cs.namespace(|| "cur is right"),
                layer.as_ref().map(|&(_, p)| p),
            )?;

            let lhs = cur;
            let rhs = witness_u256(
                cs.namespace(|| "sibling"),
                layer.as_ref().map(|&(ref sibling, _)| &sibling[..]),
            )?;

            // Conditionally swap if cur is right
            let preimage = conditionally_swap_u256(
                cs.namespace(|| "conditional swap"),
                &lhs[..],
                &rhs[..],
                &cur_is_right,
            )?;

            cur = sha256_block_no_padding(cs.namespace(|| "hash of this layer"), &preimage)?;
        }

        // enforce must be true if the value is nonzero
        let enforce = AllocatedBit::alloc(
            cs.namespace(|| "enforce"),
            value.get_value().map(|n| n != 0),
        )?;

        // value * (1 - enforce) = 0
        // If `value` is zero, `enforce` _can_ be zero.
        // If `value` is nonzero, `enforce` _must_ be one.
        cs.enforce(
            || "enforce validity",
            |_| value.lc(),
            |lc| lc + CS::one() - enforce.get_variable(),
            |lc| lc,
        );

        assert_eq!(cur.len(), rt.len());

        // Check that the anchor (exposed as a public input)
        // is equal to the merkle tree root that we calculated
        // for this note
        for (i, (cur, rt)) in cur.into_iter().zip(rt.iter()).enumerate() {
            // (cur - rt) * enforce = 0
            // if enforce is zero, cur and rt can be different
            // if enforce is one, they must be equal
            cs.enforce(
                || format!("conditionally enforce correct root for bit {}", i),
                |_| cur.lc(CS::one(), Scalar::one()) - &rt.lc(CS::one(), Scalar::one()),
                |lc| lc + enforce.get_variable(),
                |lc| lc,
            );
        }

        Ok(InputNote { mac, nf })
    }
}
```

在返回mac和nf之前，上述方法做以下几件事：

1. 见证`a_sk`、`rho`、`r`，计算并见证了`a_pk`、`nf`、`mac`和`cm`，方法`prf_a_pk`、`prf_nf`、`prf_pk`的定义可见[此处](https://github.com/zcash/librustzcash/blob/main/zcash_proofs/src/circuit/sprout/prfs.rs)，最终都调用了以下`prf`方法，组装一个vector后调用bellman提供的[sha256_block_no_padding](https://github.com/zkcrypto/bellman/blob/main/src/gadgets/sha256.rs#L29)，而方法`note_comm`则调用了bellman一个有padding的[sha256](https://github.com/zkcrypto/bellman/blob/main/src/gadgets/sha256.rs#L47)方法；

```rust
fn prf<Scalar, CS>(
    cs: CS,
    a: bool,
    b: bool,
    c: bool,
    d: bool,
    x: &[Boolean],
    y: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(x.len(), 252);
    assert_eq!(y.len(), 256);

    let mut image = vec![
        Boolean::constant(a),
        Boolean::constant(b),
        Boolean::constant(c),
        Boolean::constant(d),
    ];
    image.extend(x.iter().cloned());
    image.extend(y.iter().cloned());
    // 对于prf_a_pk，image = vec![true, true, false, false].extend(a_sk).extend(一个全0组)
    // 对于prf_nf，image = vec![true, true, true, false].extend(a_sk).extend(rho)
    // 对于prf_pk，image = vec![false, nonce, false, false].extend(a_sk).extend(h_sig)，nonce对inputs[0]为false，对inputs[1]为true
    // image总长度均为4 + 252 + 256
    assert_eq!(image.len(), 512);

    sha256_block_no_padding(cs, &image)
}
```

```rust
pub fn note_comm<Scalar, CS>(
    cs: CS,
    a_pk: &[Boolean],
    value: &[Boolean],
    rho: &[Boolean],
    r: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(a_pk.len(), 256);
    assert_eq!(value.len(), 64);
    assert_eq!(rho.len(), 256);
    assert_eq!(r.len(), 256);

    let mut image = vec![
        Boolean::constant(true),
        Boolean::constant(false),
        Boolean::constant(true),
        Boolean::constant(true),
        Boolean::constant(false),
        Boolean::constant(false),
        Boolean::constant(false),
        Boolean::constant(false),
    ];
    image.extend(a_pk.iter().cloned());
    image.extend(value.iter().cloned());
    image.extend(rho.iter().cloned());
    image.extend(r.iter().cloned());
    // image = vec![true, false, true, true, false, false, false, false].extend(a_pk).extend(value).extend(rho).extend(r)
    sha256(cs, &image)
}
```

2. 检查merkle tree path，这里会有些复杂，单独拿出来看，

```rust
// Witness into the merkle tree
let mut cur = cm;

// 迭代是顺序的，但是上面提到，我们的auth_path是倒序的
for (i, layer) in auth_path.iter().enumerate() {
    let cs = &mut cs.namespace(|| format!("layer {}", i));

    // path的每一层都是两个node，一左一右，这里记录是否为右节点
    // 这里用到一个AllocatedBit电路
    // pub fn alloc<Scalar, CS>(mut cs: CS, value: Option<bool>) -> Result<Self, SynthesisError>
    // where
    //     Scalar: PrimeField,
    //     CS: ConstraintSystem<Scalar>,
    // {
    //     let var = cs.alloc(
    //         || "boolean",
    //         || {
    //             if *value.get()? {
    //                 Ok(Scalar::one())
    //             } else {
    //                 Ok(Scalar::zero())
    //             }
    //         },
    //     )?;
    //
    //     // Constrain: (1 - a) * a = 0
    //     // This constrains a to be either 0 or 1.
    //     cs.enforce(
    //         || "boolean constraint",
    //         |lc| lc + CS::one() - var,
    //         |lc| lc + var,
    //         |lc| lc,
    //     );
    //
    //     Ok(AllocatedBit {
    //         variable: var,
    //         value,
    //     })
    // }
    let cur_is_right = AllocatedBit::alloc(
        cs.namespace(|| "cur is right"),
        layer.as_ref().map(|&(_, p)| p),
    )?;

    // 取cur为左哈希lhs，取兄弟节点为右哈希rhs
    let lhs = cur;
    let rhs = witness_u256(
        cs.namespace(|| "sibling"),
        layer.as_ref().map(|&(ref sibling, _)| &sibling[..]),
    )?;

    // 当cur实际为右，做一个conditionally_swap，方法如下
    // /// Swaps two 256-bit blobs conditionally, returning the
    // /// 512-bit concatenation.
    // pub fn conditionally_swap_u256<Scalar, CS>(
    //     mut cs: CS,
    //     lhs: &[Boolean],
    //     rhs: &[Boolean],
    //     condition: &AllocatedBit,
    // ) -> Result<Vec<Boolean>, SynthesisError>
    // where
    //     Scalar: PrimeField,
    //     CS: ConstraintSystem<Scalar>,
    // {
    //     // 先验证左右哈希的长度都为256
    //     assert_eq!(lhs.len(), 256);
    //     assert_eq!(rhs.len(), 256);
    //
    //     let mut new_lhs = vec![];
    //     let mut new_rhs = vec![];
    //
    //     // 然后逐个字节进行处理
    //     for (i, (lhs, rhs)) in lhs.iter().zip(rhs.iter()).enumerate() {
    //         let cs = &mut cs.namespace(|| format!("bit {}", i));
    //
    //         // 如果cur_is_right，取rhs.get_value()，否则取lhs.get_value()
    //         let x = Boolean::from(AllocatedBit::alloc(
    //             cs.namespace(|| "x"),
    //             condition
    //                 .get_value()
    //                 .and_then(|v| if v { rhs.get_value() } else { lhs.get_value() }),
    //         )?);
    //
    //         // 下面是这个逻辑的电路实现
    //         // x = (1-condition)lhs + (condition)rhs
    //         // x = lhs - lhs(condition) + rhs(condition)
    //         // x - lhs = condition (rhs - lhs)
    //         // if condition is zero, we don't swap, so
    //         //   x - lhs = 0
    //         //   x = lhs
    //         // if condition is one, we do swap, so
    //         //   x - lhs = rhs - lhs
    //         //   x = rhs
    //         cs.enforce(
    //             || "conditional swap for x",
    //             |lc| lc + &rhs.lc(CS::one(), Scalar::one()) - &lhs.lc(CS::one(), Scalar::one()),
    //             |lc| lc + condition.get_variable(),
    //             |lc| lc + &x.lc(CS::one(), Scalar::one()) - &lhs.lc(CS::one(), Scalar::one()),
    //         );
    //
    //         // y值就是反过来，如果cur_is_right，取lhs.get_value()，否则取rhs.get_value()
    //         let y = Boolean::from(AllocatedBit::alloc(
    //             cs.namespace(|| "y"),
    //             condition
    //                 .get_value()
    //                 .and_then(|v| if v { lhs.get_value() } else { rhs.get_value() }),
    //         )?);
    //
    //         // 然后是再一次的电路实现
    //         // y = (1-condition)rhs + (condition)lhs
    //         // y - rhs = condition (lhs - rhs)
    //         cs.enforce(
    //             || "conditional swap for y",
    //             |lc| lc + &lhs.lc(CS::one(), Scalar::one()) - &rhs.lc(CS::one(), Scalar::one()),
    //             |lc| lc + condition.get_variable(),
    //             |lc| lc + &y.lc(CS::one(), Scalar::one()) - &rhs.lc(CS::one(), Scalar::one()),
    //         );
    //
    //         new_lhs.push(x);
    //         new_rhs.push(y);
    //     }
    //     // 组装后，f = new_lhs.extend(new_rhs)
    //     let mut f = new_lhs;
    //     f.extend(new_rhs);
    //
    //     // 验证f的长度为256 + 256
    //     assert_eq!(f.len(), 512);
    //
    //     Ok(f)
    // }
    let preimage = conditionally_swap_u256(
        cs.namespace(|| "conditional swap"),
        &lhs[..],
        &rhs[..],
        &cur_is_right,
    )?;

    // 此时preimage代表了merkel subtree的这一层，传入做一个sha256，重新赋值给cur做迭代验证
    cur = sha256_block_no_padding(cs.namespace(|| "hash of this layer"), &preimage)?;
}
```

3. enforce检验input的`value`是否0，还是上面的`AllocatedBit`电路，传入的是`n != 0`；
4. 然后再enforce `value * (1 - enforce) = 0`，但是这里这个`value`理应是`nonce`，不知道是代码错还是我理解错，因为这个式子恒等于0，如果`nonce`是0，那么即便`enforce`为0也可以通过验证，如果`nonce`是1，那`enforce`必须为1，也就是`n != 0`;
5. 最后check merkel root，前面我们已经通过迭代在电路中算出一个root `cur`，这里逐字节比较`cur`和`rt`，enforce `(cur - rt) * enforce = 0`，这里如果`enforce == 0`代表input为空；
6. 返回组装好的InputNote。

我们也能找到关于交易输出的[OutputNote](https://github.com/zcash/librustzcash/blob/main/zcash_proofs/src/circuit/sprout/output.rs)电路，

```rust
impl OutputNote {
    pub fn compute<Scalar, CS>(
        mut cs: CS,
        a_pk: Option<PayingKey>,
        value: &NoteValue,
        r: Option<CommitmentRandomness>,
        phi: &[Boolean],
        h_sig: &[Boolean],
        nonce: bool,
    ) -> Result<Self, SynthesisError>
    where
        Scalar: PrimeField,
        CS: ConstraintSystem<Scalar>,
    {
        let rho = prf_rho(cs.namespace(|| "rho"), phi, h_sig, nonce)?;

        let a_pk = witness_u256(
            cs.namespace(|| "a_pk"),
            a_pk.as_ref().map(|a_pk| &a_pk.0[..]),
        )?;

        let r = witness_u256(cs.namespace(|| "r"), r.as_ref().map(|r| &r.0[..]))?;

        let cm = note_comm(
            cs.namespace(|| "cm computation"),
            &a_pk,
            &value.bits_le(),
            &rho,
            &r,
        )?;

        Ok(OutputNote { cm })
    }
}
```

类似的，以上方法也做了这几件事，计算`rho`，见证`a_pk`和`r`，然后计算一个新的`cm`，调用的方法和`InputNote`调用的一样，不用再赘述了。

在三个电路中我们可以看到名为`ConstraintSystem`的参数空间贯穿始终。在下面的证明生成中我们可以看到它的初始化。

### bellman计算

#### 证明生成

准备好电路和参数后，方法再调用到[zkcrypto/bellman/src/groth16/prover.rs](https://github.com/zkcrypto/bellman/blob/main/src/groth16/prover.rs)生成证明。

```rust
pub fn create_random_proof<E, C, R, P: ParameterSource<E>>(
    circuit: C, // 我们的电路
    params: P,  // 公用参数，这里调用时是JoinSplit，也就是Sprout的公用参数
    mut rng: &mut R,    // RNG
) -> Result<Proof<E>, SynthesisError>
where
    E: Engine,
    E::Fr: PrimeFieldBits,
    C: Circuit<E::Fr>,
    R: RngCore,
{
    let r = E::Fr::random(&mut rng);
    let s = E::Fr::random(&mut rng);

    create_proof::<E, C, P>(circuit, params, r, s)
}

#[allow(clippy::many_single_char_names)]
pub fn create_proof<E, C, P: ParameterSource<E>>(
    circuit: C,
    mut params: P,
    r: E::Fr,
    s: E::Fr,
) -> Result<Proof<E>, SynthesisError>
where
    E: Engine,
    E::Fr: PrimeFieldBits,
    C: Circuit<E::Fr>,
{
    // 这里的prover使用了ProvingAssignment的约束系统，包含了一部分预计算的过程
    let mut prover = ProvingAssignment {
        a_aux_density: DensityTracker::new(),
        b_input_density: DensityTracker::new(),
        b_aux_density: DensityTracker::new(),
        a: vec![],
        b: vec![],
        c: vec![],
        input_assignment: vec![],
        aux_assignment: vec![],
    };

    // 将statement装载到input_assignment
    prover.alloc_input(|| "", || Ok(E::Fr::one()))?;

    // 装载电路，AC => R1CS，我们在上面已经准备好了电路的synthesize逻辑，这里传入了prover的cs
    circuit.synthesize(&mut prover)?;

    // 计算s⋅A(x)，s⋅B(x)，s⋅C(x)，后面可以在ProvingAssignment的ConstraintSystem看到
    for i in 0..prover.input_assignment.len() {
        prover.enforce(|| "", |lc| lc + Variable(Index::Input(i)), |lc| lc, |lc| lc);
    }

    let worker = Worker::new();

    // 获得vk
    let vk = params.get_vk(prover.input_assignment.len())?;

    // 计算h(x)
    let h = {
        // R1CS => QAP
        // 下面计算h(x) = (s⋅A(x) * s⋅B(x) - s⋅C(x)) / t(x)
        // 这里a、b、c分别是计算好的s⋅A(x)，s⋅B(x)，s⋅C(x)
        // 详细解析可以看，https://learnblockchain.cn/article/705
        let mut a = EvaluationDomain::from_coeffs(prover.a)?;
        let mut b = EvaluationDomain::from_coeffs(prover.b)?;
        let mut c = EvaluationDomain::from_coeffs(prover.c)?;

        // 以下使用的操作定义在，https://github.com/zkcrypto/bellman/blob/main/src/domain.rs
        a.ifft(&worker);
        a.coset_fft(&worker);
        b.ifft(&worker);
        b.coset_fft(&worker);
        c.ifft(&worker);
        c.coset_fft(&worker);

        a.mul_assign(&worker, &b);
        drop(b);
        a.sub_assign(&worker, &c);
        drop(c);
        a.divide_by_z_on_coset(&worker);
        a.icoset_fft(&worker);
        let mut a = a.into_coeffs();
        let a_len = a.len() - 1;
        a.truncate(a_len);
        // TODO: parallelize if it's even helpful
        let a = Arc::new(a.into_iter().map(|s| s.0.into()).collect::<Vec<_>>());

        // multiexp定义在https://github.com/zkcrypto/bellman/blob/main/src/multiexp.rs
        multiexp(&worker, params.get_h(a.len())?, FullDensity, a)
    };

    // TODO: parallelize if it's even helpful
    // 在已知h(x)后完成proof的剩余计算
    let input_assignment = Arc::new(
        prover
            .input_assignment
            .into_iter()
            .map(|s| s.into())
            .collect::<Vec<_>>(),
    );
    let aux_assignment = Arc::new(
        prover
            .aux_assignment
            .into_iter()
            .map(|s| s.into())
            .collect::<Vec<_>>(),
    );

    let l = multiexp(
        &worker,
        params.get_l(aux_assignment.len())?,
        FullDensity,
        aux_assignment.clone(),
    );

    let a_aux_density_total = prover.a_aux_density.get_total_density();

    let (a_inputs_source, a_aux_source) =
        params.get_a(input_assignment.len(), a_aux_density_total)?;

    let a_inputs = multiexp(
        &worker,
        a_inputs_source,
        FullDensity,
        input_assignment.clone(),
    );
    let a_aux = multiexp(
        &worker,
        a_aux_source,
        Arc::new(prover.a_aux_density),
        aux_assignment.clone(),
    );

    let b_input_density = Arc::new(prover.b_input_density);
    let b_input_density_total = b_input_density.get_total_density();
    let b_aux_density = Arc::new(prover.b_aux_density);
    let b_aux_density_total = b_aux_density.get_total_density();

    let (b_g1_inputs_source, b_g1_aux_source) =
        params.get_b_g1(b_input_density_total, b_aux_density_total)?;

    let b_g1_inputs = multiexp(
        &worker,
        b_g1_inputs_source,
        b_input_density.clone(),
        input_assignment.clone(),
    );
    let b_g1_aux = multiexp(
        &worker,
        b_g1_aux_source,
        b_aux_density.clone(),
        aux_assignment.clone(),
    );

    let (b_g2_inputs_source, b_g2_aux_source) =
        params.get_b_g2(b_input_density_total, b_aux_density_total)?;

    let b_g2_inputs = multiexp(
        &worker,
        b_g2_inputs_source,
        b_input_density,
        input_assignment,
    );
    let b_g2_aux = multiexp(&worker, b_g2_aux_source, b_aux_density, aux_assignment);

    if bool::from(vk.delta_g1.is_identity() | vk.delta_g2.is_identity()) {
        // If this element is zero, someone is trying to perform a
        // subversion-CRS attack.
        return Err(SynthesisError::UnexpectedIdentity);
    }

    let mut g_a = vk.delta_g1 * r;
    AddAssign::<&E::G1Affine>::add_assign(&mut g_a, &vk.alpha_g1);
    let mut g_b = vk.delta_g2 * s;
    AddAssign::<&E::G2Affine>::add_assign(&mut g_b, &vk.beta_g2);
    let mut g_c;
    {
        let mut rs = r;
        rs.mul_assign(&s);

        g_c = vk.delta_g1 * rs;
        AddAssign::<&E::G1>::add_assign(&mut g_c, &(vk.alpha_g1 * s));
        AddAssign::<&E::G1>::add_assign(&mut g_c, &(vk.beta_g1 * r));
    }
    let mut a_answer = a_inputs.wait()?;
    AddAssign::<&E::G1>::add_assign(&mut a_answer, &a_aux.wait()?);
    AddAssign::<&E::G1>::add_assign(&mut g_a, &a_answer);
    MulAssign::<E::Fr>::mul_assign(&mut a_answer, s);
    AddAssign::<&E::G1>::add_assign(&mut g_c, &a_answer);

    let mut b1_answer: E::G1 = b_g1_inputs.wait()?;
    AddAssign::<&E::G1>::add_assign(&mut b1_answer, &b_g1_aux.wait()?);
    let mut b2_answer = b_g2_inputs.wait()?;
    AddAssign::<&E::G2>::add_assign(&mut b2_answer, &b_g2_aux.wait()?);

    AddAssign::<&E::G2>::add_assign(&mut g_b, &b2_answer);
    MulAssign::<E::Fr>::mul_assign(&mut b1_answer, r);
    AddAssign::<&E::G1>::add_assign(&mut g_c, &b1_answer);
    AddAssign::<&E::G1>::add_assign(&mut g_c, &h.wait()?);
    AddAssign::<&E::G1>::add_assign(&mut g_c, &l.wait()?);

    Ok(Proof {
        a: g_a.to_affine(),
        b: g_b.to_affine(),
        c: g_c.to_affine(),
    })
}
```

以上方法直接接受电路`C`和参数`P`，完成了最后的证明生成过程。一条完整的Sprout生成JoinSplit证明的调用线到此为止。

#### ProvingAssignment

在方法的开头，我们的prover被初始化为`ProvingAssignment`类型，后者在[代码声明](https://github.com/zkcrypto/bellman/blob/main/src/groth16/prover.rs#L57)中是如下的结构体：

```rust
struct ProvingAssignment<S: PrimeField> {
    // Density of queries
    a_aux_density: DensityTracker,
    b_input_density: DensityTracker,
    b_aux_density: DensityTracker,

    // Evaluations of A, B, C polynomials
    a: Vec<Scalar<S>>,
    b: Vec<Scalar<S>>,
    c: Vec<Scalar<S>>,

    // Assignments of variables
    input_assignment: Vec<S>,
    aux_assignment: Vec<S>,
}
```

并且实现了属于自己的`ConstraintSystem`，对应如下代码，

```rust
impl<S: PrimeField> ConstraintSystem<S> for ProvingAssignment<S> {
    type Root = Self;

    // 常规
    fn alloc<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<S, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.aux_assignment.push(f()?);
        self.a_aux_density.add_element();
        self.b_aux_density.add_element();

        Ok(Variable(Index::Aux(self.aux_assignment.len() - 1)))
    }

    // 常规
    fn alloc_input<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<S, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.input_assignment.push(f()?);
        self.b_input_density.add_element();

        Ok(Variable(Index::Input(self.input_assignment.len() - 1)))
    }

    // 计算s⋅A(x)，s⋅B(x)，s⋅C(x)，然后装载到自己的a，b，c
    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<S>) -> LinearCombination<S>,
        LB: FnOnce(LinearCombination<S>) -> LinearCombination<S>,
        LC: FnOnce(LinearCombination<S>) -> LinearCombination<S>,
    {
        let a = a(LinearCombination::zero());
        let b = b(LinearCombination::zero());
        let c = c(LinearCombination::zero());

        self.a.push(Scalar(eval(
            &a,
            // Inputs have full density in the A query
            // because there are constraints of the
            // form x * 0 = 0 for each input.
            None,
            Some(&mut self.a_aux_density),
            &self.input_assignment,
            &self.aux_assignment,
        )));
        self.b.push(Scalar(eval(
            &b,
            Some(&mut self.b_input_density),
            Some(&mut self.b_aux_density),
            &self.input_assignment,
            &self.aux_assignment,
        )));
        self.c.push(Scalar(eval(
            &c,
            // There is no C polynomial query,
            // though there is an (beta)A + (alpha)B + C
            // query for all aux variables.
            // However, that query has full density.
            None,
            None,
            &self.input_assignment,
            &self.aux_assignment,
        )));
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self) {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}
```

## 交易构建

直接上Zcash的交易结构定义，在[zcash/zcash/src/primitives/transaction.h](https://github.com/zcash/zcash/blob/master/src/primitives/transaction.h#L703)，

```cpp
/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
private:
    // ......
protected:
    // ......
public:
    typedef std::array<unsigned char, 64> joinsplit_sig_t;
    typedef std::array<unsigned char, 64> binding_sig_t;

    // Transactions that include a list of JoinSplits are >= version 2.
    static const int32_t SPROUT_MIN_CURRENT_VERSION = 1;
    static const int32_t SPROUT_MAX_CURRENT_VERSION = 2;
    static const int32_t OVERWINTER_MIN_CURRENT_VERSION = 3;
    static const int32_t OVERWINTER_MAX_CURRENT_VERSION = 3;
    static const int32_t SAPLING_MIN_CURRENT_VERSION = 4;
    static const int32_t SAPLING_MAX_CURRENT_VERSION = 4;
    static const int32_t NU5_MIN_CURRENT_VERSION = 4;
    static const int32_t NU5_MAX_CURRENT_VERSION = 5;

    static_assert(SPROUT_MIN_CURRENT_VERSION >= SPROUT_MIN_TX_VERSION,
                  "standard rule for tx version should be consistent with network rule");

    static_assert(OVERWINTER_MIN_CURRENT_VERSION >= OVERWINTER_MIN_TX_VERSION,
                  "standard rule for tx version should be consistent with network rule");

    static_assert( (OVERWINTER_MAX_CURRENT_VERSION <= OVERWINTER_MAX_TX_VERSION &&
                    OVERWINTER_MAX_CURRENT_VERSION >= OVERWINTER_MIN_CURRENT_VERSION),
                  "standard rule for tx version should be consistent with network rule");

    static_assert(SAPLING_MIN_CURRENT_VERSION >= SAPLING_MIN_TX_VERSION,
                  "standard rule for tx version should be consistent with network rule");

    static_assert( (SAPLING_MAX_CURRENT_VERSION <= SAPLING_MAX_TX_VERSION &&
                    SAPLING_MAX_CURRENT_VERSION >= SAPLING_MIN_CURRENT_VERSION),
                  "standard rule for tx version should be consistent with network rule");

    static_assert(NU5_MIN_CURRENT_VERSION >= SAPLING_MIN_TX_VERSION,
                  "standard rule for tx version should be consistent with network rule");

    static_assert( (NU5_MAX_CURRENT_VERSION <= ZIP225_MAX_TX_VERSION &&
                    NU5_MAX_CURRENT_VERSION >= NU5_MIN_CURRENT_VERSION),
                  "standard rule for tx version should be consistent with network rule");

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    // 公用属性
    const bool fOverwintered{false};
    const int32_t nVersion{0};
    const uint32_t nVersionGroupId{0};
    // Transparent Tx
    const std::vector<CTxIn> vin;
    const std::vector<CTxOut> vout;
    const uint32_t nLockTime{0};
    const uint32_t nExpiryHeight{0};
    // Sapling Tx
    const std::vector<SpendDescription> vShieldedSpend;
    const std::vector<OutputDescription> vShieldedOutput;
    // Sprout Tx
    const std::vector<JSDescription> vJoinSplit;
    const Ed25519VerificationKey joinSplitPubKey;
    const Ed25519Signature joinSplitSig;
    const binding_sig_t bindingSig = {{0}};

    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction();

    /** Convert a CMutableTransaction into a CTransaction. */
    CTransaction(const CMutableTransaction &tx);
    CTransaction(CMutableTransaction &&tx);

    CTransaction& operator=(const CTransaction& tx);

    // ......
}
```

然后是JSDescription的定义，在[同一文件](https://github.com/zcash/zcash/blob/master/src/primitives/transaction.h#L378)，

```cpp
class JSDescription
{
public:
    // These values 'enter from' and 'exit to' the value
    // pool, respectively.
    // 注，typedef int64_t CAmount;
    CAmount vpub_old{0};
    CAmount vpub_new{0};

    // JoinSplits are always anchored to a root in the note
    // commitment tree at some point in the blockchain
    // history or in the history of the current
    // transaction.
    uint256 anchor;

    // Nullifiers are used to prevent double-spends. They
    // are derived from the secrets placed in the note
    // and the secret spend-authority key known by the
    // spender.
    std::array<uint256, ZC_NUM_JS_INPUTS> nullifiers;

    // Note commitments are introduced into the commitment
    // tree, blinding the public about the values and
    // destinations involved in the JoinSplit. The presence of
    // a commitment in the note commitment tree is required
    // to spend it.
    std::array<uint256, ZC_NUM_JS_OUTPUTS> commitments;

    // Ephemeral key
    uint256 ephemeralKey;

    // Ciphertexts
    // These contain trapdoors, values and other information
    // that the recipient needs, including a memo field. It
    // is encrypted using the scheme implemented in crypto/NoteEncryption.cpp
    std::array<ZCNoteEncryption::Ciphertext, ZC_NUM_JS_OUTPUTS> ciphertexts = {{ {{0}} }};

    // Random seed
    uint256 randomSeed;

    // MACs
    // The verification of the JoinSplit requires these MACs
    // to be provided as an input.
    std::array<uint256, ZC_NUM_JS_INPUTS> macs;

    // JoinSplit proof
    // This is a zk-SNARK which ensures that this JoinSplit is valid.
    libzcash::SproutProof proof;

    JSDescription(): vpub_old(0), vpub_new(0) { }

    // ......
}
```

不出意外，和我们在生成证明时候揭露的公共参数基本相同。可惜的是，Sprout协议下构建交易的过程已经被移除，我们只能在历史代码中找到对`ZCJoinSplit`的[使用](https://github.com/zcash/zcash/blob/v3.0.0/src/transaction_builder.cpp#L367)，选取了一部分如下，

```cpp
//
// Sprout JoinSplits
//

unsigned char joinSplitPrivKey[crypto_sign_SECRETKEYBYTES];
crypto_sign_keypair(mtx.joinSplitPubKey.begin(), joinSplitPrivKey);

// Create Sprout JSDescriptions
if (!jsInputs.empty() || !jsOutputs.empty()) {
    try {
        CreateJSDescriptions();
    } catch (JSDescException e) {
        librustzcash_sapling_proving_ctx_free(ctx);
        return TransactionBuilderResult(e.what());
    } catch (std::runtime_error e) {
        librustzcash_sapling_proving_ctx_free(ctx);
        throw e;
    }
}

// ......

// Create Sprout joinSplitSig
if (crypto_sign_detached(
    mtx.joinSplitSig.data(), NULL,
    dataToBeSigned.begin(), 32,
    joinSplitPrivKey) != 0)
{
    return TransactionBuilderResult("Failed to create Sprout joinSplitSig");
}

// Sanity check Sprout joinSplitSig
if (crypto_sign_verify_detached(
    mtx.joinSplitSig.data(),
    dataToBeSigned.begin(), 32,
    mtx.joinSplitPubKey.begin()) != 0)
{
    return TransactionBuilderResult("Sprout joinSplitSig sanity check failed");
}
```

我们先看JoinSplit的序列构建过程，

```cpp
void TransactionBuilder::CreateJSDescriptions()
{
    // Copy jsInputs and jsOutputs to more flexible containers
    std::deque<libzcash::JSInput> jsInputsDeque;
    for (auto jsInput : jsInputs) {
        jsInputsDeque.push_back(jsInput);
    }
    std::deque<libzcash::JSOutput> jsOutputsDeque;
    for (auto jsOutput : jsOutputs) {
        jsOutputsDeque.push_back(jsOutput);
    }

    // If we have no Sprout shielded inputs, then we do the simpler more-leaky
    // process where we just create outputs directly. We save the chaining logic,
    // at the expense of leaking the sums of pairs of output values in vpub_old.
    // 当JoinSplit的input数量为0，则vpub_old = outputs[0].value + outputs[1].value,
    // 意味着发送者从自己的公开资产销毁vpub_old，并将等量的隐匿资产铸造到Sprout资金池
    // vpub_old是公开的，所以会称泄露了output value的总量信息
    if (jsInputs.empty()) {
        // Create joinsplits, where each output represents a zaddr recipient.
        while (jsOutputsDeque.size() > 0) {
            // Default array entries are dummy inputs and outputs
            std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS> vjsin;
            std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS> vjsout;
            uint64_t vpub_old = 0;

            for (int n = 0; n < ZC_NUM_JS_OUTPUTS && jsOutputsDeque.size() > 0; n++) {
                vjsout[n] = jsOutputsDeque.front();
                jsOutputsDeque.pop_front();

                // Funds are removed from the value pool and enter the private pool
                vpub_old += vjsout[n].value;
            }

            std::array<size_t, ZC_NUM_JS_INPUTS> inputMap;
            std::array<size_t, ZC_NUM_JS_OUTPUTS> outputMap;
            CreateJSDescription(vpub_old, 0, vjsin, vjsout, inputMap, outputMap);
        }
        return;
    }

    // At this point, we are guaranteed to have at least one input note.
    // Use address of first input note as the temporary change address.
    auto changeKey = jsInputsDeque.front().key;
    auto changeAddress = changeKey.address();

    CAmount jsChange = 0;          // this is updated after each joinsplit
    int changeOutputIndex = -1;    // this is updated after each joinsplit if jsChange > 0
    bool vpubOldProcessed = false; // updated when vpub_old for taddr inputs is set in first joinsplit
    bool vpubNewProcessed = false; // updated when vpub_new for miner fee and taddr outputs is set in last joinsplit

    CAmount valueOut = 0;
    for (auto jsInput : jsInputs) {
        valueOut += jsInput.note.value();
    }
    for (auto jsOutput : jsOutputs) {
        valueOut -= jsOutput.value;
    }
    CAmount vpubOldTarget = valueOut < 0 ? -valueOut : 0;
    CAmount vpubNewTarget = valueOut > 0 ? valueOut : 0;

    // Keep track of treestate within this transaction
    boost::unordered_map<uint256, SproutMerkleTree, CCoinsKeyHasher> intermediates;
    std::vector<uint256> previousCommitments;

    while (!vpubNewProcessed) {
        // Default array entries are dummy inputs and outputs
        std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS> vjsin;
        std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS> vjsout;
        uint64_t vpub_old = 0;
        uint64_t vpub_new = 0;

        // Set vpub_old in the first joinsplit
        if (!vpubOldProcessed) {
            vpub_old += vpubOldTarget; // funds flowing from public pool
            vpubOldProcessed = true;
        }

        CAmount jsInputValue = 0;
        uint256 jsAnchor;

        JSDescription prevJoinSplit;

        // Keep track of previous JoinSplit and its commitments
        if (mtx.vJoinSplit.size() > 0) {
            prevJoinSplit = mtx.vJoinSplit.back();
        }

        // If there is no change, the chain has terminated so we can reset the tracked treestate.
        if (jsChange == 0 && mtx.vJoinSplit.size() > 0) {
            intermediates.clear();
            previousCommitments.clear();
        }

        //
        // Consume change as the first input of the JoinSplit.
        //
        if (jsChange > 0) {
            // Update tree state with previous joinsplit
            SproutMerkleTree tree;
            {
                // assert that coinsView is not null
                assert(coinsView);
                // We do not check cs_coinView because we do not set this in testing
                // assert(cs_coinsView);
                LOCK(cs_coinsView);
                auto it = intermediates.find(prevJoinSplit.anchor);
                if (it != intermediates.end()) {
                    tree = it->second;
                } else if (!coinsView->GetSproutAnchorAt(prevJoinSplit.anchor, tree)) {
                    throw JSDescException("Could not find previous JoinSplit anchor");
                }
            }

            assert(changeOutputIndex != -1);
            assert(changeOutputIndex < prevJoinSplit.commitments.size());
            boost::optional<SproutWitness> changeWitness;
            int n = 0;
            for (const uint256& commitment : prevJoinSplit.commitments) {
                tree.append(commitment);
                previousCommitments.push_back(commitment);
                if (!changeWitness && changeOutputIndex == n++) {
                    changeWitness = tree.witness();
                } else if (changeWitness) {
                    changeWitness.get().append(commitment);
                }
            }
            assert(changeWitness.has_value());
            jsAnchor = tree.root();
            intermediates.insert(std::make_pair(tree.root(), tree)); // chained js are interstitial (found in between block boundaries)

            // Decrypt the change note's ciphertext to retrieve some data we need
            ZCNoteDecryption decryptor(changeKey.receiving_key());
            auto hSig = prevJoinSplit.h_sig(*sproutParams, mtx.joinSplitPubKey);
            try {
                auto plaintext = libzcash::SproutNotePlaintext::decrypt(
                    decryptor,
                    prevJoinSplit.ciphertexts[changeOutputIndex],
                    prevJoinSplit.ephemeralKey,
                    hSig,
                    (unsigned char)changeOutputIndex);

                auto note = plaintext.note(changeAddress);
                vjsin[0] = libzcash::JSInput(changeWitness.get(), note, changeKey);

                jsInputValue += plaintext.value();

                LogPrint("zrpcunsafe", "spending change (amount=%s)\n", FormatMoney(plaintext.value()));

            } catch (const std::exception& e) {
                throw JSDescException("Error decrypting output note of previous JoinSplit");
            }
        }

        //
        // Consume spendable non-change notes
        //
        for (int n = (jsChange > 0) ? 1 : 0; n < ZC_NUM_JS_INPUTS && jsInputsDeque.size() > 0; n++) {
            auto jsInput = jsInputsDeque.front();
            jsInputsDeque.pop_front();

            // Add history of previous commitments to witness
            if (jsChange > 0) {
                for (const uint256& commitment : previousCommitments) {
                    jsInput.witness.append(commitment);
                }
                if (jsAnchor != jsInput.witness.root()) {
                    throw JSDescException("Witness for spendable note does not have same anchor as change input");
                }
            }

            // The jsAnchor is null if this JoinSplit is at the start of a new chain
            if (jsAnchor.IsNull()) {
                jsAnchor = jsInput.witness.root();
            }

            jsInputValue += jsInput.note.value();
            vjsin[n] = jsInput;
        }

        // Find recipient to transfer funds to
        libzcash::JSOutput recipient;
        if (jsOutputsDeque.size() > 0) {
            recipient = jsOutputsDeque.front();
            jsOutputsDeque.pop_front();
        }
        // `recipient` is now either a valid recipient, or a dummy output with value = 0

        // Reset change
        jsChange = 0;
        CAmount outAmount = recipient.value;

        // Set vpub_new in the last joinsplit (when there are no more notes to spend or zaddr outputs to satisfy)
        if (jsOutputsDeque.empty() && jsInputsDeque.empty()) {
            assert(!vpubNewProcessed);
            if (jsInputValue < vpubNewTarget) {
                throw JSDescException(strprintf("Insufficient funds for vpub_new %s", FormatMoney(vpubNewTarget)));
            }
            outAmount += vpubNewTarget;
            vpub_new += vpubNewTarget; // funds flowing back to public pool
            vpubNewProcessed = true;
            jsChange = jsInputValue - outAmount;
            assert(jsChange >= 0);
        } else {
            // This is not the last joinsplit, so compute change and any amount still due to the recipient
            if (jsInputValue > outAmount) {
                jsChange = jsInputValue - outAmount;
            } else if (outAmount > jsInputValue) {
                // Any amount due is owed to the recipient.  Let the miners fee get paid first.
                CAmount due = outAmount - jsInputValue;
                libzcash::JSOutput recipientDue(recipient.addr, due);
                recipientDue.memo = recipient.memo;
                jsOutputsDeque.push_front(recipientDue);

                // reduce the amount being sent right now to the value of all inputs
                recipient.value = jsInputValue;
            }
        }

        // create output for recipient
        assert(ZC_NUM_JS_OUTPUTS == 2); // If this changes, the logic here will need to be adjusted
        vjsout[0] = recipient;

        // create output for any change
        if (jsChange > 0) {
            vjsout[1] = libzcash::JSOutput(changeAddress, jsChange);

            LogPrint("zrpcunsafe", "generating note for change (amount=%s)\n", FormatMoney(jsChange));
        }

        std::array<size_t, ZC_NUM_JS_INPUTS> inputMap;
        std::array<size_t, ZC_NUM_JS_OUTPUTS> outputMap;
        CreateJSDescription(vpub_old, vpub_new, vjsin, vjsout, inputMap, outputMap);

        if (jsChange > 0) {
            changeOutputIndex = -1;
            for (size_t i = 0; i < outputMap.size(); i++) {
                if (outputMap[i] == 1) {
                    changeOutputIndex = i;
                }
            }
            assert(changeOutputIndex != -1);
        }
    }
}
```

## Sprout验证

在zk-SNARK的证明中，Sprout只证明了以下几件事：

1. Prover持有能够生成指定commitment的note参数和spending key；
2. Prover消耗的note来自于Sprout Merkel Tree，且value合法；
3. Prover给出的merkel tree path有效；
4. Prover铸造了一些新note，且value也合法；
5. Prover铸造新note的value总和等于他销毁掉的value总和。

Prover当然还公开了包括`rt`、`h_sig`、`nf`、`mac`、`cm`、`vpub_old`、`vpub_new`在内的public inputs，再用它们构建了遮蔽的、不会被盗用的交易，但是还有一些问题没有解决：

1. 区块中不同交易的anchor root不同时如何检查state；
2. commitment证明存在被二次计算后盗用的可能。

zk-SNARKs verify的过程发生在[`CheckTransaction()`](https://github.com/zcash/zcash/blob/master/src/main.cpp#L1381)，

```cpp
bool CheckTransaction(const CTransaction& tx, CValidationState &state,
                      ProofVerifier& verifier)
{
    // Don't count coinbase transactions because mining skews the count
    if (!tx.IsCoinBase()) {
        transactionsValidated.increment();
    }

    if (!CheckTransactionWithoutProofVerification(tx, state)) {
        return false;
    } else {
        // Ensure that zk-SNARKs verify
        for (const JSDescription &joinsplit : tx.vJoinSplit) {
            if (!verifier.VerifySprout(joinsplit, tx.joinSplitPubKey)) {
                return state.DoS(100, error("CheckTransaction(): joinsplit does not verify"),
                                    REJECT_INVALID, "bad-txns-joinsplit-verification-failed");
            }
        }

        // Sapling zk-SNARK proofs are checked in librustzcash_sapling_check_{spend,output},
        // called from ContextualCheckTransaction.

        // Orchard zk-SNARK proofs are checked by orchard::AuthValidator::Batch.

        return true;
    }
}
```

其中的`CheckTransactionWithoutProofVerification()`也定义在在[zcash/zcash/src/main.cpp](https://github.com/zcash/zcash/blob/master/src/main.cpp#L1418)，

```cpp
/**
 * Basic checks that don't depend on any context.
 *
 * This function must obey the following contract: it must reject transactions
 * that are invalid according to the transaction's embedded version
 * information, but it may accept transactions that are valid with respect to
 * embedded version information but are invalid with respect to current
 * consensus rules.
 */
bool CheckTransactionWithoutProofVerification(const CTransaction& tx, CValidationState &state)
{
    /**
     * Previously:
     * 1. The consensus rule below was:
     *        if (tx.nVersion < SPROUT_MIN_TX_VERSION) { ... }
     *    which checked if tx.nVersion fell within the range:
     *        INT32_MIN <= tx.nVersion < SPROUT_MIN_TX_VERSION
     * 2. The parser allowed tx.nVersion to be negative
     *
     * Now:
     * 1. The consensus rule checks to see if tx.Version falls within the range:
     *        0 <= tx.nVersion < SPROUT_MIN_TX_VERSION
     * 2. The previous consensus rule checked for negative values within the range:
     *        INT32_MIN <= tx.nVersion < 0
     *    This is unnecessary for Overwinter transactions since the parser now
     *    interprets the sign bit as fOverwintered, so tx.nVersion is always >=0,
     *    and when Overwinter is not active ContextualCheckTransaction rejects
     *    transactions with fOverwintered set.  When fOverwintered is set,
     *    this function and ContextualCheckTransaction will together check to
     *    ensure tx.nVersion avoids the following ranges:
     *        0 <= tx.nVersion < OVERWINTER_MIN_TX_VERSION
     *        OVERWINTER_MAX_TX_VERSION < tx.nVersion <= INT32_MAX
     */
    if (!tx.fOverwintered && tx.nVersion < SPROUT_MIN_TX_VERSION) {
        return state.DoS(100, error("CheckTransaction(): version too low"),
                         REJECT_INVALID, "bad-txns-version-too-low");
    }
    else if (tx.fOverwintered) {
        if (tx.nVersion < OVERWINTER_MIN_TX_VERSION) {
            return state.DoS(100, error("CheckTransaction(): overwinter version too low"),
                REJECT_INVALID, "bad-tx-overwinter-version-too-low");
        }
        if (tx.nVersionGroupId != OVERWINTER_VERSION_GROUP_ID &&
                tx.nVersionGroupId != SAPLING_VERSION_GROUP_ID &&
                tx.nVersionGroupId != ZIP225_VERSION_GROUP_ID &&
                tx.nVersionGroupId != ZFUTURE_VERSION_GROUP_ID) {
            return state.DoS(100, error("CheckTransaction(): unknown tx version group id"),
                    REJECT_INVALID, "bad-tx-version-group-id");
        }
    }
    auto orchard_bundle = tx.GetOrchardBundle();

    // Transactions must contain some potential source of funds. This rejects
    // obviously-invalid transaction constructions early, but cannot prevent
    // e.g. a pure Sapling transaction with only dummy spends (which is
    // undetectable). Contextual checks ensure that only one of Sprout
    // joinsplits or Orchard actions may be present.
    // Note that orchard_bundle.SpendsEnabled() is false when no
    // Orchard bundle is present, i.e. when nActionsOrchard == 0.
    if (tx.vin.empty() &&
        tx.vJoinSplit.empty() &&
        tx.vShieldedSpend.empty() &&
        !orchard_bundle.SpendsEnabled())
    {
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-no-source-of-funds");
    }
    // Transactions must contain some potential useful sink of funds.  This
    // rejects obviously-invalid transaction constructions early, but cannot
    // prevent e.g. a pure Sapling transaction with only dummy outputs (which
    // is undetectable), and does not prevent transparent transactions from
    // sending all funds to miners.  Contextual checks ensure that only one of
    // Sprout joinsplits or Orchard actions may be present.
    // Note that orchard_bundle.OutputsEnabled() is false when no
    // Orchard bundle is present, i.e. when nActionsOrchard == 0.
    if (tx.vout.empty() &&
        tx.vJoinSplit.empty() &&
        tx.vShieldedOutput.empty() &&
        !orchard_bundle.OutputsEnabled())
    {
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-no-sink-of-funds");
    }

    // Size limits
    static_assert(MAX_BLOCK_SIZE >= MAX_TX_SIZE_AFTER_SAPLING); // sanity
    static_assert(MAX_TX_SIZE_AFTER_SAPLING > MAX_TX_SIZE_BEFORE_SAPLING); // sanity
    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) > MAX_TX_SIZE_AFTER_SAPLING)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    for (const CTxOut& txout : tx.vout)
    {
        if (txout.nValue < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Check for non-zero valueBalanceSapling when there are no Sapling inputs or outputs
    if (tx.vShieldedSpend.empty() && tx.vShieldedOutput.empty() && tx.GetValueBalanceSapling() != 0) {
        return state.DoS(100, error("CheckTransaction(): tx.valueBalanceSapling has no sources or sinks"),
                            REJECT_INVALID, "bad-txns-valuebalance-nonzero");
    }

    // Check for overflow valueBalanceSapling
    if (tx.GetValueBalanceSapling() > MAX_MONEY || tx.GetValueBalanceSapling() < -MAX_MONEY) {
        return state.DoS(100, error("CheckTransaction(): abs(tx.valueBalanceSapling) too large"),
                            REJECT_INVALID, "bad-txns-valuebalance-toolarge");
    }

    if (tx.GetValueBalanceSapling() <= 0) {
        // NB: negative valueBalanceSapling "takes" money from the transparent value pool just as outputs do
        nValueOut += -tx.GetValueBalanceSapling();

        if (!MoneyRange(nValueOut)) {
            return state.DoS(100, error("CheckTransaction(): txout total out of range"),
                                REJECT_INVALID, "bad-txns-txouttotal-toolarge");
        }
    }

    // nSpendsSapling, nOutputsSapling, and nActionsOrchard MUST all be less than 2^16
    size_t max_elements = (1 << 16) - 1;
    if (tx.vShieldedSpend.size() > max_elements) {
        return state.DoS(
            100,
            error("CheckTransaction(): 2^16 or more Sapling spends"),
            REJECT_INVALID, "bad-tx-too-many-sapling-spends");
    }
    if (tx.vShieldedOutput.size() > max_elements) {
        return state.DoS(
            100,
            error("CheckTransaction(): 2^16 or more Sapling outputs"),
            REJECT_INVALID, "bad-tx-too-many-sapling-outputs");
    }
    if (orchard_bundle.GetNumActions() > max_elements) {
        return state.DoS(
            100,
            error("CheckTransaction(): 2^16 or more Orchard actions"),
            REJECT_INVALID, "bad-tx-too-many-orchard-actions");
    }

    // Check that if neither Orchard spends nor outputs are enabled, the transaction contains
    // no Orchard actions. This subsumes the check that valueBalanceOrchard must equal zero
    // in the case that both spends and outputs are disabled.
    if (orchard_bundle.GetNumActions() > 0 && !orchard_bundle.OutputsEnabled() && !orchard_bundle.SpendsEnabled()) {
        return state.DoS(
            100,
            error("CheckTransaction(): Orchard actions are present, but flags do not permit Orchard spends or outputs"),
            REJECT_INVALID, "bad-tx-orchard-flags-disable-actions");
    }

    auto valueBalanceOrchard = orchard_bundle.GetValueBalance();

    // Check for overflow valueBalanceOrchard
    if (valueBalanceOrchard > MAX_MONEY || valueBalanceOrchard < -MAX_MONEY) {
        return state.DoS(100, error("CheckTransaction(): abs(tx.valueBalanceOrchard) too large"),
                         REJECT_INVALID, "bad-txns-valuebalance-toolarge");
    }

    if (valueBalanceOrchard <= 0) {
        // NB: negative valueBalanceOrchard "takes" money from the transparent value pool just as outputs do
        nValueOut += -valueBalanceOrchard;

        if (!MoneyRange(nValueOut)) {
            return state.DoS(100, error("CheckTransaction(): txout total out of range"),
                             REJECT_INVALID, "bad-txns-txouttotal-toolarge");
        }
    }

    // Ensure that joinsplit values are well-formed
    for (const JSDescription& joinsplit : tx.vJoinSplit)
    {
        if (joinsplit.vpub_old < 0) {
            return state.DoS(100, error("CheckTransaction(): joinsplit.vpub_old negative"),
                             REJECT_INVALID, "bad-txns-vpub_old-negative");
        }

        if (joinsplit.vpub_new < 0) {
            return state.DoS(100, error("CheckTransaction(): joinsplit.vpub_new negative"),
                             REJECT_INVALID, "bad-txns-vpub_new-negative");
        }

        if (joinsplit.vpub_old > MAX_MONEY) {
            return state.DoS(100, error("CheckTransaction(): joinsplit.vpub_old too high"),
                             REJECT_INVALID, "bad-txns-vpub_old-toolarge");
        }

        if (joinsplit.vpub_new > MAX_MONEY) {
            return state.DoS(100, error("CheckTransaction(): joinsplit.vpub_new too high"),
                             REJECT_INVALID, "bad-txns-vpub_new-toolarge");
        }

        if (joinsplit.vpub_new != 0 && joinsplit.vpub_old != 0) {
            return state.DoS(100, error("CheckTransaction(): joinsplit.vpub_new and joinsplit.vpub_old both nonzero"),
                             REJECT_INVALID, "bad-txns-vpubs-both-nonzero");
        }

        nValueOut += joinsplit.vpub_old;
        if (!MoneyRange(nValueOut)) {
            return state.DoS(100, error("CheckTransaction(): txout total out of range"),
                             REJECT_INVALID, "bad-txns-txouttotal-toolarge");
        }
    }

    // Ensure input values do not exceed MAX_MONEY
    // We have not resolved the txin values at this stage,
    // but we do know what the joinsplits claim to add
    // to the value pool.
    {
        CAmount nValueIn = 0;
        for (std::vector<JSDescription>::const_iterator it(tx.vJoinSplit.begin()); it != tx.vJoinSplit.end(); ++it)
        {
            nValueIn += it->vpub_new;

            if (!MoneyRange(it->vpub_new) || !MoneyRange(nValueIn)) {
                return state.DoS(100, error("CheckTransaction(): txin total out of range"),
                                 REJECT_INVALID, "bad-txns-txintotal-toolarge");
            }
        }

        // Also check for Sapling
        if (tx.GetValueBalanceSapling() >= 0) {
            // NB: positive valueBalanceSapling "adds" money to the transparent value pool, just as inputs do
            nValueIn += tx.GetValueBalanceSapling();

            if (!MoneyRange(nValueIn)) {
                return state.DoS(100, error("CheckTransaction(): txin total out of range"),
                                 REJECT_INVALID, "bad-txns-txintotal-toolarge");
            }
        }

        // Also check for Orchard
        if (valueBalanceOrchard >= 0) {
            // NB: positive valueBalanceOrchard "adds" money to the transparent value pool, just as inputs do
            nValueIn += valueBalanceOrchard;

            if (!MoneyRange(nValueIn)) {
                return state.DoS(100, error("CheckTransaction(): txin total out of range"),
                                    REJECT_INVALID, "bad-txns-txintotal-toolarge");
            }
        }
    }

    // Check for duplicate inputs
    set<COutPoint> vInOutPoints;
    for (const CTxIn& txin : tx.vin)
    {
        if (vInOutPoints.count(txin.prevout))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
        vInOutPoints.insert(txin.prevout);
    }

    // Check for duplicate joinsplit nullifiers in this transaction
    {
        set<uint256> vJoinSplitNullifiers;
        for (const JSDescription& joinsplit : tx.vJoinSplit)
        {
            for (const uint256& nf : joinsplit.nullifiers)
            {
                if (vJoinSplitNullifiers.count(nf))
                    return state.DoS(100, error("CheckTransaction(): duplicate nullifiers"),
                                REJECT_INVALID, "bad-joinsplits-nullifiers-duplicate");

                vJoinSplitNullifiers.insert(nf);
            }
        }
    }

    // Check for duplicate sapling nullifiers in this transaction
    {
        set<uint256> vSaplingNullifiers;
        for (const SpendDescription& spend_desc : tx.vShieldedSpend)
        {
            if (vSaplingNullifiers.count(spend_desc.nullifier))
                return state.DoS(100, error("CheckTransaction(): duplicate nullifiers"),
                            REJECT_INVALID, "bad-spend-description-nullifiers-duplicate");

            vSaplingNullifiers.insert(spend_desc.nullifier);
        }
    }

    // Check for duplicate orchard nullifiers in this transaction
    {
        std::set<uint256> vOrchardNullifiers;
        for (const uint256& nf : tx.GetOrchardBundle().GetNullifiers())
        {
            if (vOrchardNullifiers.count(nf))
                return state.DoS(100, error("CheckTransaction(): duplicate nullifiers"),
                            REJECT_INVALID, "bad-orchard-nullifiers-duplicate");

            vOrchardNullifiers.insert(nf);
        }
    }

    if (tx.IsCoinBase())
    {
        // There should be no joinsplits in a coinbase transaction
        if (tx.vJoinSplit.size() > 0)
            return state.DoS(100, error("CheckTransaction(): coinbase has joinsplits"),
                             REJECT_INVALID, "bad-cb-has-joinsplits");

        // A coinbase transaction cannot have spend descriptions
        if (tx.vShieldedSpend.size() > 0)
            return state.DoS(100, error("CheckTransaction(): coinbase has spend descriptions"),
                             REJECT_INVALID, "bad-cb-has-spend-description");
        // See ContextualCheckTransaction for consensus rules on coinbase output descriptions.
        if (orchard_bundle.SpendsEnabled())
            return state.DoS(100, error("CheckTransaction(): coinbase has enableSpendsOrchard set"),
                             REJECT_INVALID, "bad-cb-has-orchard-spend");

        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
    }
    else
    {
        for (const CTxIn& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");
    }

    return true;
}
```

可以看到的是，`CheckTransactionWithoutProofVerification()`只对交易的内部做了简单的去重，这不能解决我们的问题，接下来再看`VerifySprout()`，它接收我们交易中携带的JSDescription作为输入，然后又跳转向了librustzcash，

```cpp
bool ProofVerifier::VerifySprout(
    const JSDescription& jsdesc,
    const Ed25519VerificationKey& joinSplitPubKey
) {
    if (!perform_verification) {
        return true;
    }

    auto pv = SproutProofVerifier(*this, joinSplitPubKey, jsdesc);
    return std::visit(pv, jsdesc.proof);
}
```