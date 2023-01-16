# zk-SNARK (Part3)

接上文，我们已经介绍了Groth16的定义，包括参数的预设、证明的生成、验证，以及复现论据的模拟过程。接下来，我们先从Zcash的Sprout和Sapling协议入手，看一看Zcash如何实现zk-SNARK和隐匿交易。

Zcash中的zk-SNARK总是证明两件事：

1. Prover销毁了某个属于自己的Note；
2. Prover铸造了某个有效的Note给目标地址。

## Sprout证明

我们按照从下往上的顺序，先看最为基础的JoinSplit数据结构和Zcash在隐匿交易中完成的证明。

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

在上面的证明部分，我们已经知道了JoinSplit的结构组成，以及Proof证明的具体内容，接下来这部分内容将具体描述Zcash节点如何从RPC指令的参数中构建Sprout交易以及如何处理Sprout Merkel Tree。

### 交易结构

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

### 构建过程

不出意外，和我们在生成证明时候揭露的公共参数基本相同。可惜的是，Sprout协议下构建交易的过程已经被移除，我们只能在历史代码中找到对`ZCJoinSplit`的[使用](https://github.com/zcash/zcash/blob/v3.0.0/src/transaction_builder.cpp#L367)，选取了一部分如下，

```cpp
//
// Sprout JoinSplits
//

unsigned char joinSplitPrivKey[crypto_sign_SECRETKEYBYTES];
crypto_sign_keypair(mtx.joinSplitPubKey.begin(), joinSplitPrivKey);

// Create Sprout JSDescriptions
// 每个JoinSplit只能处理两个input和两个output，所以有时需要构建多个JoinSplit
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

//
// Signatures
//
auto consensusBranchId = CurrentEpochBranchId(nHeight, consensusParams);

// Empty output script.
uint256 dataToBeSigned;
CScript scriptCode;
try {
    dataToBeSigned = SignatureHash(scriptCode, mtx, NOT_AN_INPUT, SIGHASH_ALL, 0, consensusBranchId);
} catch (std::logic_error ex) {
    librustzcash_sapling_proving_ctx_free(ctx);
    return TransactionBuilderResult("Could not construct signature hash: " + std::string(ex.what()));
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
    // 这里不需要处理note的销毁，逻辑相对简单
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
    // 而当存在至少一个input时，先将第一个input的来源地址取为临时地址
    auto changeKey = jsInputsDeque.front().key;
    auto changeAddress = changeKey.address();

    CAmount jsChange = 0;          // this is updated after each joinsplit
    int changeOutputIndex = -1;    // this is updated after each joinsplit if jsChange > 0
    bool vpubOldProcessed = false; // updated when vpub_old for taddr inputs is set in first joinsplit
    bool vpubNewProcessed = false; // updated when vpub_new for miner fee and taddr outputs is set in last joinsplit

    // 计算隐私输入value减隐私输出value后的剩余值
    CAmount valueOut = 0;
    for (auto jsInput : jsInputs) {
        valueOut += jsInput.note.value();
    }
    for (auto jsOutput : jsOutputs) {
        valueOut -= jsOutput.value;
    }
    // valueOut为负时，input数量不足，将vpub_old置为非零；反之output数量不足，将vpub_new置为非零
    CAmount vpubOldTarget = valueOut < 0 ? -valueOut : 0;
    CAmount vpubNewTarget = valueOut > 0 ? valueOut : 0;

    // Keep track of treestate within this transaction
    // 记录当前的SproutMerkleTree树状态
    boost::unordered_map<uint256, SproutMerkleTree, CCoinsKeyHasher> intermediates;
    std::vector<uint256> previousCommitments;

    // 当，当前处理的JoinSplit不是交易中最后一个JoinSplit，时
    while (!vpubNewProcessed) {
        // Default array entries are dummy inputs and outputs
        std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS> vjsin;
        std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS> vjsout;
        uint64_t vpub_old = 0;
        uint64_t vpub_new = 0;

        // Set vpub_old in the first joinsplit
        // 当，当前处理的JoinSplit是交易中第一个JoinSplit时，处理vpub_old
        if (!vpubOldProcessed) {
            vpub_old += vpubOldTarget; // funds flowing from public pool
            vpubOldProcessed = true;
        }

        // 处理state anchor
        CAmount jsInputValue = 0;
        uint256 jsAnchor;

        JSDescription prevJoinSplit;

        // Keep track of previous JoinSplit and its commitments
        if (mtx.vJoinSplit.size() > 0) {
            prevJoinSplit = mtx.vJoinSplit.back();
        }

        // If there is no change, the chain has terminated so we can reset the tracked treestate.
        // 若之前的JoinSplit没有未处理完的余额，则清理掉缓存
        if (jsChange == 0 && mtx.vJoinSplit.size() > 0) {
            intermediates.clear();
            previousCommitments.clear();
        }

        //
        // Consume change as the first input of the JoinSplit.
        //
        // 若之前的JoinSplit有未处理完的余额，则将上一个JoinSplit铸造的零钱output作为自己的第一个input
        if (jsChange > 0) {
            // Update tree state with previous joinsplit
            // 找到上一个JoinSplit锚定的初始树状态
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
            // 将上一个JoinSplit新加的commitment加入树中，取出见证后的witness
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
            // 将上一个JoinSplit更改后的树状态记录为自己的锚定状态
            jsAnchor = tree.root();
            intermediates.insert(std::make_pair(tree.root(), tree)); // chained js are interstitial (found in between block boundaries)

            // Decrypt the change note's ciphertext to retrieve some data we need
            ZCNoteDecryption decryptor(changeKey.receiving_key());
            auto hSig = prevJoinSplit.h_sig(*sproutParams, mtx.joinSplitPubKey);
            try {
                // 取出零钱output位置的note数据
                auto plaintext = libzcash::SproutNotePlaintext::decrypt(
                    decryptor,
                    prevJoinSplit.ciphertexts[changeOutputIndex],
                    prevJoinSplit.ephemeralKey,
                    hSig,
                    (unsigned char)changeOutputIndex);

                // 将未使用完的零钱作为当前JoinSplit的input[0]
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
        // 正式处理当前JoinSplit的数据，如果继承了零钱，则有两个input需要处理
        for (int n = (jsChange > 0) ? 1 : 0; n < ZC_NUM_JS_INPUTS && jsInputsDeque.size() > 0; n++) {
            // 取出input队列的第一个，作为当前JoinSplit将要处理的对象
            auto jsInput = jsInputsDeque.front();
            jsInputsDeque.pop_front();

            // Add history of previous commitments to witness
            // 如果继承零钱，则JoinSplit的anchor root为上一个JoinSplit的终结状态
            if (jsChange > 0) {
                for (const uint256& commitment : previousCommitments) {
                    jsInput.witness.append(commitment);
                }
                if (jsAnchor != jsInput.witness.root()) {
                    throw JSDescException("Witness for spendable note does not have same anchor as change input");
                }
            }

            // The jsAnchor is null if this JoinSplit is at the start of a new chain
            // 如果不继承零钱，则JoinSplit的anchor root为input note见证后的树状态
            if (jsAnchor.IsNull()) {
                jsAnchor = jsInput.witness.root();
            }

            jsInputValue += jsInput.note.value();
            vjsin[n] = jsInput;
        }

        // Find recipient to transfer funds to
        libzcash::JSOutput recipient;
        if (jsOutputsDeque.size() > 0) {
            // 取出output队列的第一个，作为当前JoinSplit将要处理的对象
            recipient = jsOutputsDeque.front();
            jsOutputsDeque.pop_front();
        }
        // `recipient` is now either a valid recipient, or a dummy output with value = 0

        // Reset change
        // 重置零钱标记
        jsChange = 0;
        // outAmount可以是一个值（有确切接收对象）或者零（全部output都已经处理完了）
        CAmount outAmount = recipient.value;

        // Set vpub_new in the last joinsplit (when there are no more notes to spend or zaddr outputs to satisfy)
        if (jsOutputsDeque.empty() && jsInputsDeque.empty()) {
            // 当全部input和output处理完成，处理vpub_new
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
            // 否则尝试满足recipient.value，若jsInputValue不足，则拆分到下一个JoinSplit进行满足
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
        // 如果jsInputValue - recipient.value有剩余，额外铸造一个零钱note
        if (jsChange > 0) {
            vjsout[1] = libzcash::JSOutput(changeAddress, jsChange);

            LogPrint("zrpcunsafe", "generating note for change (amount=%s)\n", FormatMoney(jsChange));
        }

        std::array<size_t, ZC_NUM_JS_INPUTS> inputMap;
        std::array<size_t, ZC_NUM_JS_OUTPUTS> outputMap;
        CreateJSDescription(vpub_old, vpub_new, vjsin, vjsout, inputMap, outputMap);

        // 记录零钱note的index，结束后转到下一个JoinSplit的处理
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

这段代码逻辑稍复杂，这里用注释的方式进行了详细的解释。简单来说，

1. 在一笔Sprout交易中，Zcash用一个JoinSplit序列来处理所有的隐匿转账；
2. 第一个JoinSplit接收公开资产，最后一个JoinSplit铸造公开资产；
3. 每一个JoinSplit都尝试处理一对input和output，`input[0]`位置可选的处理上一个JoinSplit结余的零钱，而`output[1]`位置可选的铸造JoinSplit未处理完的零钱；
4. 当`output.value > input.value`时，output也将被拆分到下一个JoinSplit继续处理；
5. 有零钱继承关系的JoinSplit使用连续的树状态，即产生零钱的JoinSplit终结状态为处理零钱的JoinSplit起始状态；
6. 没有零钱继承关系的JoinSplit使用间隔的树状态，即JoinSplit的起始状态为`input[0]`铸造时的终结状态。

后面的签名相比之下较为简单，方法`crypto_sign_detached`调用到了外部的libsodium完成签名，而被签名的数据`dataToBeSigned`则是包含了交易完整终结状态上下文`mtx`的哈希。

## Sprout验证

在zk-SNARK的证明中，Sprout证明了以下几件事：

1. Prover持有能够生成指定input note commitment的参数，即spending key；
2. Prover消耗一些来自于有效Sprout Merkel Subtree的input note，且它们的和合法；
3. Prover铸造了一些新的output note给某个receiving key，且value也合法；
4. Prover铸造新note的value总和加上公开的`vpub_new`等于他销毁掉的value总和加上公开的`vpub_old`。

Prover当然还公开了包括`rt`、`h_sig`、`nf`、`mac`、`cm`、`vpub_old`、`vpub_new`在内的public inputs，再用它们构建了遮蔽的、不会被盗用的交易，但是交易的验证，尤其是间隙树状态的异步验证还没有解决，需要我们继续去寻找。

Zcash中一个完整的矿工验证逻辑包含四步：验证区块头、验证区块、验证区块上下文和连接区块。其中区块头的验证和Bitcoin基本相同，因此这一节中我们将描述其他的后三步，

```cpp
// NOTE: CheckBlockHeader is called by CheckBlock
if (!ContextualCheckBlockHeader(block, state, chainparams, pindexPrev))
    return false;
// The following may be duplicative of the `CheckBlock` call within `ConnectBlock`
if (!CheckBlock(block, state, chainparams, verifier, false, fCheckMerkleRoot, true))
    return false;
if (!ContextualCheckBlock(block, state, chainparams, pindexPrev, true))
    return false;
if (!ConnectBlock(block, state, &indexDummy, viewNew, chainparams, true, blockChecks))
    return false;
assert(state.IsValid());

return true;
```

### 上下文无关验证

根据一些众所周知的常识，作为Verifier的Zcash节点首先以区块的形式接收到交易，我们可以在[zcash/zcash/src/main.cpp](https://github.com/zcash/zcash/blob/master/src/main.cpp#L4753)找到这个入口，

```cpp
bool CheckBlock(const CBlock& block,
                CValidationState& state,
                const CChainParams& chainparams,
                ProofVerifier& verifier,
                bool fCheckPOW,
                bool fCheckMerkleRoot,
                bool fCheckTransactions)
{
    // These are checks that are independent of context.

    if (block.fChecked)
        return true;

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, chainparams, fCheckPOW))
        return false;

    // Check the merkle root.
    if (fCheckMerkleRoot) {
        bool mutated;
        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.DoS(100, error("CheckBlock(): hashMerkleRoot mismatch"),
                             REJECT_INVALID, "bad-txnmrklroot", true);

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.DoS(100, error("CheckBlock(): duplicate transaction"),
                             REJECT_INVALID, "bad-txns-duplicate", true);
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.

    // Size limits
    if (block.vtx.empty() || block.vtx.size() > MAX_BLOCK_SIZE || ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return state.DoS(100, error("CheckBlock(): size limits failed"),
                         REJECT_INVALID, "bad-blk-length");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0].IsCoinBase())
        return state.DoS(100, error("CheckBlock(): first tx is not coinbase"),
                         REJECT_INVALID, "bad-cb-missing");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i].IsCoinBase())
            return state.DoS(100, error("CheckBlock(): more than one coinbase"),
                             REJECT_INVALID, "bad-cb-multiple");

    // skip all transaction checks if this flag is not set
    if (!fCheckTransactions) return true;

    // Check transactions
    for (const CTransaction& tx : block.vtx)
        if (!CheckTransaction(tx, state, verifier))
            return error("CheckBlock(): CheckTransaction of %s failed with %s",
                tx.GetHash().ToString(),
                FormatStateMessage(state));

    unsigned int nSigOps = 0;
    for (const CTransaction& tx : block.vtx)
    {
        nSigOps += GetLegacySigOpCount(tx);
    }
    if (nSigOps > MAX_BLOCK_SIGOPS)
        return state.DoS(100, error("CheckBlock(): out-of-bounds SigOpCount"),
                         REJECT_INVALID, "bad-blk-sigops", true);

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;

    return true;
}
```

以上方法完成了区块的一部分检查，这部分检查如同注释所说，是上下文无关的形式上校验，包括了：

1. 区块头的PoW验证；
2. 区块的Merkel Root验证；
3. 区块内交易的去重；
4. 区块大小的验证；
5. 区块内交易的验证；
6. 区块使用SigOp数的验证。

我们或许会关注交易如何在这里去重，但是下面的代码告诉我们这里只发生了区块内的去重，同样是上下文无关的，

```cpp
uint256 ComputeMerkleRoot(std::vector<uint256> hashes, bool* mutated) {
    bool mutation = false;
    while (hashes.size() > 1) {
        if (mutated) {
            for (size_t pos = 0; pos + 1 < hashes.size(); pos += 2) {
                if (hashes[pos] == hashes[pos + 1]) mutation = true;
            }
        }
        if (hashes.size() & 1) {
            hashes.push_back(hashes.back());
        }
        SHA256D64(hashes[0].begin(), hashes[0].begin(), hashes.size() / 2);
        hashes.resize(hashes.size() / 2);
    }
    if (mutated) *mutated = mutation;
    if (hashes.size() == 0) return uint256();
    return hashes[0];
}

uint256 BlockMerkleRoot(const CBlock& block, bool* mutated)
{
    std::vector<uint256> leaves;
    leaves.resize(block.vtx.size());
    for (size_t s = 0; s < block.vtx.size(); s++) {
        leaves[s] = block.vtx[s].GetHash();
    }
    return ComputeMerkleRoot(std::move(leaves), mutated);
}
```

Zcash交易验证的过程发生在[`CheckTransaction()`](https://github.com/zcash/zcash/blob/master/src/main.cpp#L1381)，对应如下代码，

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

其中的`CheckTransactionWithoutProofVerification()`也定义在在[zcash/zcash/src/main.cpp](https://github.com/zcash/zcash/blob/master/src/main.cpp#L1418)，下面截取其中和Sprout有关的一部分，

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
    // ......

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

    // ......

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

        // ......
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

    // ......

    if (tx.IsCoinBase())
    {
        // There should be no joinsplits in a coinbase transaction
        if (tx.vJoinSplit.size() > 0)
            return state.DoS(100, error("CheckTransaction(): coinbase has joinsplits"),
                             REJECT_INVALID, "bad-cb-has-joinsplits");

        // ......
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

可以看到的是，`CheckTransactionWithoutProofVerification()`对交易的内部做了进一步去重，又对一些公开的数值进行了有效性验证。

接下来再看`VerifySprout()`，它接收我们交易中携带的JSDescription作为输入，然后又跳转向了librustzcash，

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

毫无疑问，上述方法也只是对Groth16的证明进行了算法上的验证。

### 上下文验证

上下文有关的区块验证同样发生在[zcash/zcash/src/main.cpp](https://github.com/zcash/zcash/blob/master/src/main.cpp#L4896)，对应下面的代码，

```cpp
bool ContextualCheckBlock(
    const CBlock& block, CValidationState& state,
    const CChainParams& chainparams, CBlockIndex * const pindexPrev,
    bool fCheckTransactions)
{
    const int nHeight = pindexPrev == NULL ? 0 : pindexPrev->nHeight + 1;
    const Consensus::Params& consensusParams = chainparams.GetConsensus();

    if (fCheckTransactions) {
        // Check that all transactions are finalized
        for (const CTransaction& tx : block.vtx) {

            // Check transaction contextually against consensus rules at block height
            if (!ContextualCheckTransaction(tx, state, chainparams, nHeight, true)) {
                return false; // Failure reason has been set in validation state object
            }

            int nLockTimeFlags = 0;
            int64_t nLockTimeCutoff = (nLockTimeFlags & LOCKTIME_MEDIAN_TIME_PAST)
                                    ? pindexPrev->GetMedianTimePast()
                                    : block.GetBlockTime();
            if (!IsFinalTx(tx, nHeight, nLockTimeCutoff)) {
                return state.DoS(10, error("%s: contains a non-final transaction", __func__),
                                 REJECT_INVALID, "bad-txns-nonfinal");
            }
        }
    }

    // Enforce BIP 34 rule that the coinbase starts with serialized block height.
    // In Zcash this has been enforced since launch, except that the genesis
    // block didn't include the height in the coinbase (see Zcash protocol spec
    // section '6.8 Bitcoin Improvement Proposals').
    if (nHeight > 0)
    {
        CScript expect = CScript() << nHeight;
        if (block.vtx[0].vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0].vin[0].scriptSig.begin())) {
            return state.DoS(100, error("%s: block height mismatch in coinbase", __func__),
                             REJECT_INVALID, "bad-cb-height");
        }
    }

    // ZIP 203: From NU5 onwards, nExpiryHeight is set to the block height in coinbase
    // transactions.
    if (consensusParams.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_NU5)) {
        if (block.vtx[0].nExpiryHeight != nHeight) {
            return state.DoS(100, error("%s: block height mismatch in nExpiryHeight", __func__),
                             REJECT_INVALID, "bad-cb-height");
        }
    }

    if (consensusParams.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_CANOPY)) {
    // Funding streams are checked inside ContextualCheckTransaction.
    // This empty conditional branch exists to enforce this ZIP 207 consensus rule:
    //
    //     Once the Canopy network upgrade activates, the existing consensus rule for
    //     payment of the Founders' Reward is no longer active.
    } else if ((nHeight > 0) && (nHeight <= consensusParams.GetLastFoundersRewardBlockHeight(nHeight))) {
        // Coinbase transaction must include an output sending 20% of
        // the block subsidy to a Founders' Reward script, until the last Founders'
        // Reward block is reached, with exception of the genesis block.
        // The last Founders' Reward block is defined as the block just before the
        // first subsidy halving block, which occurs at halving_interval + slow_start_shift.
        bool found = false;

        for (const CTxOut& output : block.vtx[0].vout) {
            if (output.scriptPubKey == chainparams.GetFoundersRewardScriptAtHeight(nHeight)) {
                if (output.nValue == (GetBlockSubsidy(nHeight, consensusParams) / 5)) {
                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            return state.DoS(100, error("%s: founders reward missing", __func__),
                             REJECT_INVALID, "cb-no-founders-reward");
        }
    }

    return true;
}
```

上述方法，以及该方法中调用的`ContextualCheckTransaction()`，都是对区块或者交易是否符合网络当前协议版本进行检查，主要以区块链参数`chainparams`和当前高度`nHeight`为输入，返回验证结果`state`。这里对这块验证简单概括，我们看一下`ContextualCheckTransaction()`方法的开头部分即可，

```cpp
/**
 * Check a transaction contextually against a set of consensus rules valid at a given block height.
 *
 * Notes:
 * 1. AcceptToMemoryPool calls CheckTransaction and this function.
 * 2. ProcessNewBlock calls AcceptBlock, which calls CheckBlock (which calls CheckTransaction)
 *    and ContextualCheckBlock (which calls this function).
 * 3. For consensus rules that relax restrictions (where a transaction that is invalid at
 *    nHeight can become valid at a later height), we make the bans conditional on not
 *    being in Initial Block Download mode.
 * 4. The isInitBlockDownload argument is a function parameter to assist with testing.
 */
bool ContextualCheckTransaction(
        const CTransaction& tx,
        CValidationState &state,
        const CChainParams& chainparams,
        const int nHeight,
        const bool isMined,
        bool (*isInitBlockDownload)(const Consensus::Params&))
{
    const int DOS_LEVEL_BLOCK = 100;
    // DoS level set to 10 to be more forgiving.
    const int DOS_LEVEL_MEMPOOL = 10;

    // For constricting rules, we don't need to account for IBD mode.
    auto dosLevelConstricting = isMined ? DOS_LEVEL_BLOCK : DOS_LEVEL_MEMPOOL;
    // For rules that are relaxing (or might become relaxing when a future
    // network upgrade is implemented), we need to account for IBD mode.
    auto dosLevelPotentiallyRelaxing = isMined ? DOS_LEVEL_BLOCK : (
        isInitBlockDownload(chainparams.GetConsensus()) ? 0 : DOS_LEVEL_MEMPOOL);

    auto consensus = chainparams.GetConsensus();
    auto consensusBranchId = CurrentEpochBranchId(nHeight, consensus);

    bool overwinterActive = consensus.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_OVERWINTER);
    bool saplingActive = consensus.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_SAPLING);
    bool beforeOverwinter = !overwinterActive;
    bool heartwoodActive = consensus.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_HEARTWOOD);
    bool canopyActive = consensus.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_CANOPY);
    bool nu5Active = consensus.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_NU5);
    bool futureActive = consensus.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_ZFUTURE);

    assert(!saplingActive || overwinterActive); // Sapling cannot be active unless Overwinter is
    assert(!heartwoodActive || saplingActive);  // Heartwood cannot be active unless Sapling is
    assert(!canopyActive || heartwoodActive);   // Canopy cannot be active unless Heartwood is
    assert(!nu5Active || canopyActive);         // NU5 cannot be active unless Canopy is
    assert(!futureActive || nu5Active);         // ZFUTURE must include consensus rules for all supported network upgrades.

    // ......
}
```

该方法主要是随着Zcash协议的逐步升级而进行的分叉，对一些过低版本，或者存在兼容冲突的违规交易进行剔除。

### 区块连接

在满足区块头验证、上下文无关验证和上下文验证之后，我们距离认为Zcash上的某个区块或者某笔交易是合法的还差最后一步。因为并非所有的Zcash交易都是隐私遮蔽的，隐私证明数据的验证被放到了最后，也就是方法`ConnectBlock()`，这部分代码很长，但我们还是尽可能全地阅读一遍，

```cpp
bool ConnectBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindex,
                  CCoinsViewCache& view, const CChainParams& chainparams,
                  bool fJustCheck, CheckAs blockChecks)
{
    // ......

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    // 创世块的特殊情况
    if (block.GetHash() == chainparams.GetConsensus().hashGenesisBlock) {
        if (!fJustCheck) {
            view.SetBestBlock(pindex->GetBlockHash());
            // Before the genesis block, there was an empty tree
            SproutMerkleTree tree;
            pindex->hashSproutAnchor = tree.root();
            // The genesis block contained no JoinSplits
            pindex->hashFinalSproutRoot = pindex->hashSproutAnchor;
        }
        return true;
    }

    // Reject a block that results in a negative shielded value pool balance.
    // ZIP-209检查，防止某个隐匿资金池的余额变为负值
    // https://github.com/zcash/zips/blob/main/zip-0209.rst
    if (chainparams.ZIP209Enabled()) {
        // Sprout
        //
        // We can expect nChainSproutValue to be valid after the hardcoded
        // height, and this will be enforced on all descendant blocks. If
        // the node was reindexed then this will be enforced for all blocks.
        if (pindex->nChainSproutValue) {
            if (*pindex->nChainSproutValue < 0) {
                return state.DoS(100, error("ConnectBlock(): turnstile violation in Sprout shielded value pool"),
                             REJECT_INVALID, "turnstile-violation-sprout-shielded-pool");
            }
        }

        // ......
    }

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    for (const CTransaction& tx : block.vtx) {
        const CCoins* coins = view.AccessCoins(tx.GetHash());
        if (coins && !coins->IsPruned())
            return state.DoS(100, error("ConnectBlock(): tried to overwrite transaction"),
                             REJECT_INVALID, "bad-txns-BIP30");
    }

    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;

    // DERSIG (BIP66) is also always enforced, but does not have a flag.
    // 局部状态初始化
    CBlockUndo blockundo;

    CCheckQueueControl<CScriptCheck> control(fExpensiveChecks && nScriptCheckThreads ? &scriptcheckqueue : NULL);

    int64_t nTimeStart = GetTimeMicros();
    CAmount nFees = 0;
    int nInputs = 0;
    unsigned int nSigOps = 0;
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(block.vtx.size());
    blockundo.vtxundo.reserve(block.vtx.size() - 1);
    std::vector<CAddressIndexDbEntry> addressIndex;
    std::vector<CAddressUnspentDbEntry> addressUnspentIndex;
    std::vector<CSpentIndexDbEntry> spentIndex;

    // Construct the incremental merkle tree at the current
    // block position,
    // 找到三个协议各自incremental merkle tree目前合适添加新节点的位置，再验证一次结果
    auto old_sprout_tree_root = view.GetBestAnchor(SPROUT);
    // saving the top anchor in the block index as we go.
    if (!fJustCheck) {
        pindex->hashSproutAnchor = old_sprout_tree_root;
    }
    SproutMerkleTree sprout_tree;
    // This should never fail: we should always be able to get the root
    // that is on the tip of our chain
    assert(view.GetSproutAnchorAt(old_sprout_tree_root, sprout_tree));
    {
        // Consistency check: the root of the tree we're given should
        // match what we asked for.
        assert(sprout_tree.root() == old_sprout_tree_root);
    }

    SaplingMerkleTree sapling_tree;
    assert(view.GetSaplingAnchorAt(view.GetBestAnchor(SAPLING), sapling_tree));

    OrchardMerkleFrontier orchard_tree;
    if (pindex->pprev && chainparams.GetConsensus().NetworkUpgradeActive(pindex->pprev->nHeight, Consensus::UPGRADE_NU5)) {
        // Verify that the view's current state corresponds to the previous block.
        assert(pindex->pprev->hashFinalOrchardRoot == view.GetBestAnchor(ORCHARD));
        // We only call ConnectBlock() on top of the active chain's tip.
        assert(!pindex->pprev->hashFinalOrchardRoot.IsNull());

        assert(view.GetOrchardAnchorAt(pindex->pprev->hashFinalOrchardRoot, orchard_tree));
    } else {
        if (pindex->pprev) {
            assert(pindex->pprev->hashFinalOrchardRoot.IsNull());
        }
        assert(view.GetOrchardAnchorAt(OrchardMerkleFrontier::empty_root(), orchard_tree));
    }

    // Grab the consensus branch ID for this block and its parent
    // 以下两个参数主要帮助Zcash通过共识分叉点，不必重视
    auto consensusBranchId = CurrentEpochBranchId(pindex->nHeight, chainparams.GetConsensus());
    auto prevConsensusBranchId = CurrentEpochBranchId(pindex->nHeight - 1, chainparams.GetConsensus());

    size_t total_sapling_tx = 0;
    size_t total_orchard_tx = 0;

    std::vector<PrecomputedTransactionData> txdata;
    txdata.reserve(block.vtx.size()); // Required so that pointers to individual PrecomputedTransactionData don't get invalidated
    // 取出交易数据，尝试验证隐私部分合法性
    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const CTransaction &tx = block.vtx[i];
        const uint256 hash = tx.GetHash();

        nInputs += tx.vin.size();
        nSigOps += GetLegacySigOpCount(tx);
        if (nSigOps > MAX_BLOCK_SIGOPS)
            return state.DoS(100, error("ConnectBlock(): too many sigops"),
                             REJECT_INVALID, "bad-blk-sigops");

        // Coinbase transactions are the only case where this vector will not be the same
        // length as `tx.vin` (since coinbase transactions have a single synthetic input).
        // Only shielded coinbase transactions will need to produce sighashes for coinbase
        // transactions; this is handled in ZIP 244 by having the coinbase sighash be the
        // txid.
        std::vector<CTxOut> allPrevOutputs;

        // Are the shielded spends' requirements met?
        // 检测每个隐匿input的有效性，后面会提到
        if (!Consensus::CheckTxShieldedInputs(tx, state, view, 100)) {
            return false;
        }

        if (!tx.IsCoinBase())
        {
            if (!view.HaveInputs(tx))
                return state.DoS(100, error("ConnectBlock(): inputs missing/spent"),
                                 REJECT_INVALID, "bad-txns-inputs-missingorspent");

            // 找到每个input来源的output，取出放到allPrevOutputs
            for (const auto& input : tx.vin) {
                allPrevOutputs.push_back(view.GetOutputFor(input));
            }

            // insightexplorer
            // https://github.com/bitpay/bitcoin/commit/017f548ea6d89423ef568117447e61dd5707ec42#diff-7ec3c68a81efff79b6ca22ac1f1eabbaR2597
            // 将销毁的信息记录到addressIndex、addressUnspentIndex和spentIndex，它们作为局部变量，原本都为空
            if (fAddressIndex || fSpentIndex) {
                for (size_t j = 0; j < tx.vin.size(); j++) {

                    const CTxIn input = tx.vin[j];
                    const CTxOut &prevout = allPrevOutputs[j];
                    CScript::ScriptType scriptType = prevout.scriptPubKey.GetType();
                    const uint160 addrHash = prevout.scriptPubKey.AddressHash();
                    if (fAddressIndex && scriptType != CScript::UNKNOWN) {
                        // record spending activity
                        addressIndex.push_back(make_pair(
                            CAddressIndexKey(scriptType, addrHash, pindex->nHeight, i, hash, j, true),
                            prevout.nValue * -1));

                        // remove address from unspent index
                        addressUnspentIndex.push_back(make_pair(
                            CAddressUnspentKey(scriptType, addrHash, input.prevout.hash, input.prevout.n),
                            CAddressUnspentValue()));
                    }
                    if (fSpentIndex) {
                        // Add the spent index to determine the txid and input that spent an output
                        // and to find the amount and address from an input.
                        // If we do not recognize the script type, we still add an entry to the
                        // spentindex db, with a script type of 0 and addrhash of all zeroes.
                        spentIndex.push_back(make_pair(
                            CSpentIndexKey(input.prevout.hash, input.prevout.n),
                            CSpentIndexValue(hash, j, pindex->nHeight, prevout.nValue, scriptType, addrHash)));
                    }
                }
            }

            // Add in sigops done by pay-to-script-hash inputs;
            // this is to prevent a "rogue miner" from creating
            // an incredibly-expensive-to-validate block.
            // 操作数量检测，防止矿工制造过大的区块
            nSigOps += GetP2SHSigOpCount(tx, view);
            if (nSigOps > MAX_BLOCK_SIGOPS)
                return state.DoS(100, error("ConnectBlock(): too many sigops"),
                                 REJECT_INVALID, "bad-blk-sigops");
        }

        txdata.emplace_back(tx, allPrevOutputs);
        // 检测是否支付fee以及fee的来源
        if (!tx.IsCoinBase())
        {
            nFees += view.GetValueIn(tx)-tx.GetValueOut();

            std::vector<CScriptCheck> vChecks;
            if (!ContextualCheckInputs(tx, state, view, fExpensiveChecks, flags, fCacheResults, txdata.back(), chainparams.GetConsensus(), consensusBranchId, nScriptCheckThreads ? &vChecks : NULL))
                return error("ConnectBlock(): CheckInputs on %s failed with %s",
                    tx.GetHash().ToString(), FormatStateMessage(state));
            control.Add(vChecks);
        }

        // Check shielded inputs.
        // 检测每个隐匿input的上下文有效性，后面会提到
        if (!ContextualCheckShieldedInputs(
            tx,
            txdata.back(),
            state,
            view,
            saplingAuth,
            orchardAuth,
            chainparams.GetConsensus(),
            consensusBranchId,
            chainparams.GetConsensus().NetworkUpgradeActive(pindex->nHeight, Consensus::UPGRADE_NU5),
            true))
        {
            return error(
                "ConnectBlock(): ContextualCheckShieldedInputs() on %s failed with %s",
                tx.GetHash().ToString(),
                FormatStateMessage(state));
        }

        // insightexplorer
        // https://github.com/bitpay/bitcoin/commit/017f548ea6d89423ef568117447e61dd5707ec42#diff-7ec3c68a81efff79b6ca22ac1f1eabbaR2656
        // 将铸造的信息记录到addressIndex和addressUnspentIndex，它们作为局部变量，原本都为空
        if (fAddressIndex) {
            for (unsigned int k = 0; k < tx.vout.size(); k++) {
                const CTxOut &out = tx.vout[k];
                CScript::ScriptType scriptType = out.scriptPubKey.GetType();
                if (scriptType != CScript::UNKNOWN) {
                    uint160 const addrHash = out.scriptPubKey.AddressHash();

                    // record receiving activity
                    addressIndex.push_back(make_pair(
                        CAddressIndexKey(scriptType, addrHash, pindex->nHeight, i, hash, k, false),
                        out.nValue));

                    // record unspent output
                    addressUnspentIndex.push_back(make_pair(
                        CAddressUnspentKey(scriptType, addrHash, hash, k),
                        CAddressUnspentValue(out.nValue, out.scriptPubKey, pindex->nHeight)));
                }
            }
        }

        // 将销毁和铸造的结果暂存，同时准备好回滚需要的信息，以防万一
        // void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, CTxUndo &txundo, int nHeight)
        // {
        //     // mark inputs spent
        //     if (!tx.IsCoinBase()) {
        //         txundo.vprevout.reserve(tx.vin.size());
        //         for (const CTxIn &txin : tx.vin) {
        //             CCoinsModifier coins = inputs.ModifyCoins(txin.prevout.hash);
        //             unsigned nPos = txin.prevout.n;

        //             if (nPos >= coins->vout.size() || coins->vout[nPos].IsNull())
        //                 assert(false);
        //             // mark an outpoint spent, and construct undo information
        //             txundo.vprevout.push_back(CTxInUndo(coins->vout[nPos]));
        //             coins->Spend(nPos);
        //             if (coins->vout.size() == 0) {
        //                 CTxInUndo& undo = txundo.vprevout.back();
        //                 undo.nHeight = coins->nHeight;
        //                 undo.fCoinBase = coins->fCoinBase;
        //                 undo.nVersion = coins->nVersion;
        //             }
        //         }
        //     }
        //
        //     // spend nullifiers
        //     inputs.SetNullifiers(tx, true);
        //
        //     // add outputs
        //     inputs.ModifyNewCoins(tx.GetHash())->FromTx(tx, nHeight);
        // }
        CTxUndo undoDummy;
        if (i > 0) {
            blockundo.vtxundo.push_back(CTxUndo());
        }
        UpdateCoins(tx, view, i == 0 ? undoDummy : blockundo.vtxundo.back(), pindex->nHeight);

        // 将隐匿output的commitment添加到三个协议的incremental merkle tree
        for (const JSDescription &joinsplit : tx.vJoinSplit) {
            for (const uint256 &note_commitment : joinsplit.commitments) {
                // Insert the note commitments into our temporary tree.

                sprout_tree.append(note_commitment);
            }
        }

        for (const OutputDescription &outputDescription : tx.vShieldedOutput) {
            sapling_tree.append(outputDescription.cmu);
        }

        if (!orchard_tree.AppendBundle(tx.GetOrchardBundle())) {
            return state.DoS(100,
                error("ConnectBlock(): block would overfill the Orchard commitment tree."),
                REJECT_INVALID, "orchard-commitment-tree-full");
        };

        if (!(tx.vShieldedSpend.empty() && tx.vShieldedOutput.empty())) {
            total_sapling_tx += 1;
        }

        if (tx.GetOrchardBundle().IsPresent()) {
            total_orchard_tx += 1;
        }

        vPos.push_back(std::make_pair(tx.GetHash(), pos));
        pos.nTxOffset += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);
    }

    // ......

    // 将插入新节点后的tree root缓存到cacheAnchors
    // template<typename Tree, typename Cache, typename CacheIterator, typename CacheEntry>
    // void CCoinsViewCache::AbstractPushAnchor(
    //     const Tree &tree,
    //     ShieldedType type,
    //     Cache &cacheAnchors,
    //     uint256 &hash
    // )
    // {
    //     uint256 newrt = tree.root();
    //
    //     auto currentRoot = GetBestAnchor(type);
    //
    //     // We don't want to overwrite an anchor we already have.
    //     // This occurs when a block doesn't modify mapAnchors at all,
    //     // because there are no joinsplits. We could get around this a
    //     // different way (make all blocks modify mapAnchors somehow)
    //     // but this is simpler to reason about.
    //     if (currentRoot != newrt) {
    //         auto insertRet = cacheAnchors.insert(std::make_pair(newrt, CacheEntry()));
    //         CacheIterator ret = insertRet.first;
    //
    //         ret->second.entered = true;
    //         ret->second.tree = tree;
    //         ret->second.flags = CacheEntry::DIRTY;
    //
    //         if (insertRet.second) {
    //             // An insert took place
    //             cachedCoinsUsage += ret->second.tree.DynamicMemoryUsage();
    //         }
    //
    //         hash = newrt;
    //     }
    // }
    view.PushAnchor(sprout_tree);
    view.PushAnchor(sapling_tree);
    view.PushAnchor(orchard_tree);
    
    // ......

    int64_t nTime1 = GetTimeMicros(); nTimeConnect += nTime1 - nTimeStart;
    LogPrint("bench", "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs]\n", (unsigned)block.vtx.size(), 0.001 * (nTime1 - nTimeStart), 0.001 * (nTime1 - nTimeStart) / block.vtx.size(), nInputs <= 1 ? 0 : 0.001 * (nTime1 - nTimeStart) / (nInputs-1), nTimeConnect * 0.000001);

    // 计算区块奖励，并且验证区块正确支付该奖励
    CAmount blockReward = nFees + GetBlockSubsidy(pindex->nHeight, chainparams.GetConsensus());
    if (block.vtx[0].GetValueOut() > blockReward)
        return state.DoS(100,
                         error("ConnectBlock(): coinbase pays too much (actual=%d vs limit=%d)",
                               block.vtx[0].GetValueOut(), blockReward),
                               REJECT_INVALID, "bad-cb-amount");

    // ......

    if (!control.Wait())
        return state.DoS(100, false);
    int64_t nTime2 = GetTimeMicros(); nTimeVerify += nTime2 - nTimeStart;
    LogPrint("bench", "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs]\n", nInputs - 1, 0.001 * (nTime2 - nTimeStart), nInputs <= 1 ? 0 : 0.001 * (nTime2 - nTimeStart) / (nInputs-1), nTimeVerify * 0.000001);

    if (fJustCheck)
        return true;

    // Write undo information to disk
    // 写入回滚数据
    if (pindex->GetUndoPos().IsNull() || !pindex->IsValid(BLOCK_VALID_SCRIPTS))
    {
        if (pindex->GetUndoPos().IsNull()) {
            CDiskBlockPos _pos;
            if (!FindUndoPos(state, pindex->nFile, _pos, ::GetSerializeSize(blockundo, SER_DISK, CLIENT_VERSION) + 40))
                return error("ConnectBlock(): FindUndoPos failed");
            if (!UndoWriteToDisk(blockundo, _pos, pindex->pprev->GetBlockHash(), chainparams.MessageStart()))
                return AbortNode(state, "Failed to write undo data");

            // update nUndoPos in block index
            pindex->nUndoPos = _pos.nPos;
            pindex->nStatus |= BLOCK_HAVE_UNDO;
        }

        // Now that all consensus rules have been validated, set nCachedBranchId.
        // Move this if BLOCK_VALID_CONSENSUS is ever altered.
        static_assert(BLOCK_VALID_CONSENSUS == BLOCK_VALID_SCRIPTS,
            "nCachedBranchId must be set after all consensus rules have been validated.");
        if (IsActivationHeightForAnyUpgrade(pindex->nHeight, chainparams.GetConsensus())) {
            pindex->nStatus |= BLOCK_ACTIVATES_UPGRADE;
            pindex->nCachedBranchId = CurrentEpochBranchId(pindex->nHeight, chainparams.GetConsensus());
        } else if (pindex->pprev) {
            pindex->nCachedBranchId = pindex->pprev->nCachedBranchId;
        }

        pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
        setDirtyBlockIndex.insert(pindex);
    }

    if (fTxIndex)
        if (!pblocktree->WriteTxIndex(vPos))
            return AbortNode(state, "Failed to write transaction index");

    // START insightexplorer
    // 写入之前记录的索引数据用于展示
    if (fAddressIndex) {
        if (!pblocktree->WriteAddressIndex(addressIndex)) {
            return AbortNode(state, "Failed to write address index");
        }
        if (!pblocktree->UpdateAddressUnspentIndex(addressUnspentIndex)) {
            return AbortNode(state, "Failed to write address unspent index");
        }
    }
    if (fSpentIndex) {
        if (!pblocktree->UpdateSpentIndex(spentIndex)) {
            return AbortNode(state, "Failed to write spent index");
        }
    }
    // 写入其他的信息
    if (fTimestampIndex) {
        unsigned int logicalTS = pindex->nTime;
        unsigned int prevLogicalTS = 0;

        // retrieve logical timestamp of the previous block
        if (pindex->pprev)
            if (!pblocktree->ReadTimestampBlockIndex(pindex->pprev->GetBlockHash(), prevLogicalTS))
                LogPrintf("%s: Failed to read previous block's logical timestamp\n", __func__);

        if (logicalTS <= prevLogicalTS) {
            logicalTS = prevLogicalTS + 1;
            LogPrintf("%s: Previous logical timestamp is newer Actual[%d] prevLogical[%d] Logical[%d]\n", __func__, pindex->nTime, prevLogicalTS, logicalTS);
        }

        if (!pblocktree->WriteTimestampIndex(CTimestampIndexKey(logicalTS, pindex->GetBlockHash())))
            return AbortNode(state, "Failed to write timestamp index");

        if (!pblocktree->WriteTimestampBlockIndex(CTimestampBlockIndexKey(pindex->GetBlockHash()), CTimestampBlockIndexValue(logicalTS)))
            return AbortNode(state, "Failed to write blockhash index");
    }
    // END insightexplorer

    // add this block to the view's block chain
    // 将区块添加到当前区块链
    view.SetBestBlock(pindex->GetBlockHash());

    int64_t nTime3 = GetTimeMicros(); nTimeIndex += nTime3 - nTime2;
    LogPrint("bench", "    - Index writing: %.2fms [%.2fs]\n", 0.001 * (nTime3 - nTime2), nTimeIndex * 0.000001);

    return true;
}
```

除了常见的区块数据遍历和写入过程，我们需要关注到`CheckTxShieldedInputs()`和`ContextualCheckShieldedInputs()`。我们按照逻辑顺序，先看前者，

```cpp
bool CheckTxShieldedInputs(
    const CTransaction& tx,
    CValidationState& state,
    const CCoinsViewCache& view,
    int dosLevel)
{
    // Are the shielded spends' requirements met?
    auto unmetShieldedReq = view.CheckShieldedRequirements(tx);
    if (!unmetShieldedReq.has_value()) {
        auto txid = tx.GetHash().ToString();
        auto rejectCode = ShieldedReqRejectCode(unmetShieldedReq.error());
        auto rejectReason = ShieldedReqRejectReason(unmetShieldedReq.error());
        TracingDebug(
            "main", "CheckTxShieldedInputs(): shielded requirements not met",
            "txid", txid.c_str(),
            "reason", rejectReason.c_str());
        return state.DoS(dosLevel, false, rejectCode, rejectReason);
    }

    return true;
}
```

注释也说明，这是对隐匿输入合法性的验证，可以看到又调用到了`CheckShieldedRequirements()`，我们只看其中的Sprout部分，

```cpp
tl::expected<void, UnsatisfiedShieldedReq> CCoinsViewCache::CheckShieldedRequirements(const CTransaction& tx) const
{
    boost::unordered_map<uint256, SproutMerkleTree, SaltedTxidHasher> intermediates;

    // 遍历每一个JSDescription
    for (const JSDescription &joinsplit : tx.vJoinSplit)
    {
        // 首先在nullifier集合中查找是否有重复的，抛出双花错误
        for (const uint256& nullifier : joinsplit.nullifiers)
        {
            if (GetNullifier(nullifier, SPROUT)) {
                // If the nullifier is set, this transaction
                // double-spends!
                auto txid = tx.GetHash().ToString();
                auto nf = nullifier.ToString();
                TracingWarn("consensus", "Sprout double-spend detected",
                    "txid", txid.c_str(),
                    "nf", nf.c_str());
                return tl::unexpected(UnsatisfiedShieldedReq::SproutDuplicateNullifier);
            }
        }

        // 找到当前JoinSplit的状态锚点，JoinSplit的构建过程可以看前面
        // 先从intermediates找，它是一个本地变量，方便处理前后有零钱继承的JoinSplit关系
        // 再从SproutMerkleTree找，它是一个查找难度更大的结构
        // 对于第一个JoinSplit，它的state anchor会通过GetSproutAnchorAt找到，读取了cacheSproutAnchors
        // bool CCoinsViewCache::GetSproutAnchorAt(const uint256 &rt, SproutMerkleTree &tree) const {
        //     CAnchorsSproutMap::const_iterator it = cacheSproutAnchors.find(rt);
        //     if (it != cacheSproutAnchors.end()) {
        //         if (it->second.entered) {
        //             tree = it->second.tree;
        //             return true;
        //         } else {
        //             return false;
        //         }
        //     }
        //
        //     if (!base->GetSproutAnchorAt(rt, tree)) {
        //         return false;
        //     }
        //
        //     CAnchorsSproutMap::iterator ret = cacheSproutAnchors.insert(std::make_pair(rt, CAnchorsSproutCacheEntry())).first;
        //     ret->second.entered = true;
        //     ret->second.tree = tree;
        //     cachedCoinsUsage += ret->second.tree.DynamicMemoryUsage();
        //
        //     return true;
        // }
        SproutMerkleTree tree;
        auto it = intermediates.find(joinsplit.anchor);
        if (it != intermediates.end()) {
            tree = it->second;
        } else if (!GetSproutAnchorAt(joinsplit.anchor, tree)) {
            auto txid = tx.GetHash().ToString();
            auto anchor = joinsplit.anchor.ToString();
            TracingWarn("consensus", "Transaction uses unknown Sprout anchor",
                "txid", txid.c_str(),
                "anchor", anchor.c_str());
            return tl::unexpected(UnsatisfiedShieldedReq::SproutUnknownAnchor);
        }
        // 将commitment添加到树
        for (const uint256& commitment : joinsplit.commitments)
        {
            tree.append(commitment);
        }
        // 将当前的树做一个缓存，后续的零钱处理会变得简单
        intermediates.insert(std::make_pair(tree.root(), tree));
    }

    // ......

    return {};
}
```

然后是上下文检查，Sprout主要是验证了JoinSplit的签名，Sapling和Orchard做了不同的事，我们以后再做描述，

```cpp
bool ContextualCheckShieldedInputs(
        const CTransaction& tx,
        const PrecomputedTransactionData& txdata,
        CValidationState &state,
        const CCoinsViewCache &view,
        std::optional<rust::Box<sapling::BatchValidator>>& saplingAuth,
        std::optional<orchard::AuthValidator>& orchardAuth,
        const Consensus::Params& consensus,
        uint32_t consensusBranchId,
        bool nu5Active,
        bool isMined,
        bool (*isInitBlockDownload)(const Consensus::Params&))
{
    // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
    // for an attacker to attempt to split the network.
    if (!Consensus::CheckTxShieldedInputs(tx, state, view, 0)) {
        return false;
    }

    const int DOS_LEVEL_BLOCK = 100;
    // DoS level set to 10 to be more forgiving.
    const int DOS_LEVEL_MEMPOOL = 10;

    // For rules that are relaxing (or might become relaxing when a future
    // network upgrade is implemented), we need to account for IBD mode.
    auto dosLevelPotentiallyRelaxing = isMined ? DOS_LEVEL_BLOCK : (
        isInitBlockDownload(consensus) ? 0 : DOS_LEVEL_MEMPOOL);

    auto prevConsensusBranchId = PrevEpochBranchId(consensusBranchId, consensus);
    uint256 dataToBeSigned;
    uint256 prevDataToBeSigned;

    // Create signature hashes for shielded components.
    if (!tx.vJoinSplit.empty() ||
        !tx.vShieldedSpend.empty() ||
        !tx.vShieldedOutput.empty() ||
        tx.GetOrchardBundle().IsPresent())
    {
        // Empty output script.
        CScript scriptCode;
        try {
            dataToBeSigned = SignatureHash(scriptCode, tx, NOT_AN_INPUT, SIGHASH_ALL, 0, consensusBranchId, txdata);
            prevDataToBeSigned = SignatureHash(scriptCode, tx, NOT_AN_INPUT, SIGHASH_ALL, 0, prevConsensusBranchId, txdata);
        } catch (std::logic_error ex) {
            // A logic error should never occur because we pass NOT_AN_INPUT and
            // SIGHASH_ALL to SignatureHash().
            return state.DoS(100, error("ContextualCheckShieldedInputs(): error computing signature hash"),
                             REJECT_INVALID, "error-computing-signature-hash");
        }
    }

    if (!tx.vJoinSplit.empty())
    {
        if (!ed25519_verify(&tx.joinSplitPubKey, &tx.joinSplitSig, dataToBeSigned.begin(), 32)) {
            // Check whether the failure was caused by an outdated consensus
            // branch ID; if so, inform the node that they need to upgrade. We
            // only check the previous epoch's branch ID, on the assumption that
            // users creating transactions will notice their transactions
            // failing before a second network upgrade occurs.
            if (ed25519_verify(&tx.joinSplitPubKey,
                               &tx.joinSplitSig,
                               prevDataToBeSigned.begin(), 32)) {
                return state.DoS(
                    dosLevelPotentiallyRelaxing, false, REJECT_INVALID, strprintf(
                        "old-consensus-branch-id (Expected %s, found %s)",
                        HexInt(consensusBranchId),
                        HexInt(prevConsensusBranchId)));
            }
            return state.DoS(
                dosLevelPotentiallyRelaxing,
                error("ContextualCheckShieldedInputs(): invalid joinsplit signature"),
                REJECT_INVALID, "bad-txns-invalid-joinsplit-signature");
        }
    }

    // ......

    return true;
}
```

## 小结

本篇介绍了Sprout协议在Zcash中的具体实施细节，包括证明的生成、交易的构建、交易的验证和证明的验证。