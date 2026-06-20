# Algorithm Analysis: Privacy-Preserving Database Fingerprinting (NDSS 2023)

> Paper: *Privacy-Preserving Database Fingerprinting*, Ji et al., NDSS 2023  
> Section: IV (Algorithms 1–4), V (Robustness Analysis)

---

## Part 1 — Mathematical Symbols and Their Precise Meanings

### Core Parameters

| Symbol | Definition | Notes |
|--------|-----------|-------|
| `ε` | Privacy budget (ε > 0) | Smaller = stronger privacy. Controls how many LSBs to flip and with what probability |
| `Δ` | Database sensitivity = sup_{R,R'} ‖R - R'‖_F | Over all *entry-neighboring* pairs. ‖·‖_F is Frobenius norm. For integer-encoded categorical data with max value V, Δ = V |
| `K` | Number of LSBs fingerprinted per entry | K = ⌈log₂(Δ)⌉ + 1. Example: Δ=3 → K=2; Δ=4 → K=3; Δ=15 → K=4 |
| `p` | Flip probability. Each selected bit is XORed with B~Bernoulli(p) | p ≥ 1/(e^(ε/K)+1). Note: p < 0.5. A bit is *selected* for fingerprinting with probability 2p |
| `B` | Mark bit. B ~ Bernoulli(p) | B = x XOR f_l. Actual XOR operand applied to the data bit |
| `x` | Mask bit derived from PRNG | x = 0 if U₂(s) is even, x = 1 if U₂(s) is odd. Pr(x=0) = Pr(x=1) = 1/2 |
| `f` | Fingerprint bit-string for one SP | f = HMAC_Y(ID_internal). Length L bits |
| `f_l` | l-th bit of fingerprint f | l ∈ [0, L-1] |
| `L` | Fingerprint length | L = 128 bits (MD5). Sufficient if L ≥ ln(C) where C = number of SPs |

### HMAC-Related Parameters

| Symbol | Role | Implementation Note |
|--------|------|---------------------|
| `Y` | Secret key of database owner | Never shared. Used as HMAC key |
| `ID_internal` | Internal identifier for SP | Deterministic given (K_c, i). Input to HMAC. Format: Hash(K_c \|\| i) |
| `ID_external` | Publicly known SP identifier | Not directly used in HMAC; used to derive K_c or map to ID_internal |
| `HMAC_Y(ID_internal)` | Generates fingerprint f | Any secure MAC with key Y. Paper uses MD5 internally for the output length |
| `\|` | Concatenation operator | Used in: s = Y \| r^i.PrimaryKey \| t \| k |

### Pseudorandom Generator Calls

| Call | Purpose | Output |
|------|---------|--------|
| `U₁(s)` | Decide whether this bit position is selected for fingerprinting | U₁(s) mod ⌊1/(2p)⌋ == 0 → selected |
| `U₂(s)` | Determine mask bit x | x = 0 if U₂(s) is even, else x = 1 |
| `U₃(s)` | Select which fingerprint bit index to embed | l = U₃(s) mod L |

All three calls use the **same seed** `s = Y \| r^i.PrimaryKey \| t \| k`, but are the 1st, 2nd, 3rd outputs of the pseudorandom sequence generator U given that seed.

### Extraction Symbols

| Symbol | Meaning |
|--------|---------|
| `R̄` | Leaked/pirated database |
| `r̄^i_{t,k}` | k-th LSB of t-th attribute of i-th record in R̄ |
| `c₀[l]` | Counter: number of times bit position l was decoded as 0 |
| `c₁[l]` | Counter: number of times bit position l was decoded as 1 |
| `D` | Bit-match threshold for accusation. Set so P(> D matches by chance) < 1/C |

---

## Part 2 — Algorithm 1: ε-Entry-Level DP Fingerprint Insertion

**Purpose:** Given the original database R, a secret key Y, and an SP's internal ID, produce a fingerprinted copy M(R) that satisfies ε-entry-level DP.

**Inputs:**
- R: original database (N rows, T attributes)
- Y: secret key
- ID_internal: internal SP identifier
- ε: privacy budget
- Δ: database sensitivity

**Outputs:**
- M(R): fingerprinted database
- f: fingerprint bit-string (stored by owner for later detection)

### Pseudocode (reconstructed from paper Section IV-B)

```
Algorithm 1: Fingerprint Insertion

INPUT: R, Y, ID_internal, ε, Δ
OUTPUT: M(R), f

Line 1:  Compute K = ⌈log₂(Δ)⌉ + 1
           # Number of LSBs to potentially fingerprint per entry

Line 2:  Compute p = 1 / (e^(ε/K) + 1)
           # Minimum required flip probability for ε-entry-level DP

Line 3:  Generate fingerprint bit-string:
           f = HMAC_Y(ID_internal)
           # f is an L-bit string (L=128 using MD5)

Line 4:  Initialize M(R) = R (copy of original database)

Line 5:  Construct fingerprintable set P:
           P = { r^i_{t,k} | i ∈ [1,N], t ∈ [1,T], k ∈ [1, min(K, K_t)] }
           # K_t = number of bits used to encode the t-th attribute

Line 6:  For each bit position r^i_{t,k} in P:
           Set seed: s = Y || r^i.PrimaryKey || t || k
             # Deterministic seed: secret key + primary key + attribute index + bit index

Line 7:    Compute selection condition:
           if U₁(s) mod ⌊1/(2p)⌋ == 0:
             # This bit is selected for fingerprinting (occurs with probability ≥ 2p)

Line 8:      Compute mask bit:
             x = 0  if U₂(s) is even
             x = 1  if U₂(s) is odd
             # x ~ Uniform{0,1}

Line 9:      Select fingerprint bit index:
             l = U₃(s) mod L
             # l is the index into the fingerprint string f

Line 10:     Compute mark bit:
             B = x XOR f[l]
             # B ~ Bernoulli(p) because:
             #   Pr(B=1) = Pr(x=0)*Pr(f[l]=1) + Pr(x=1)*Pr(f[l]=0)
             #           = 0.5*Pr(f[l]=1) + 0.5*Pr(f[l]=0) = 0.5 ≥ p
             # But due to the selection condition, effective flip prob ≥ p

Line 11:     Modify the bit:
             M(R)[i][t][k] = r^i_{t,k} XOR B
             # Only changes the bit if B=1

Line 12: Return M(R), f
```

### Line-by-Line Explanation

| Line | Explanation |
|------|-------------|
| 1 | K ensures we have enough bits to encode the maximum difference Δ between any two neighboring entries. K = ⌈log₂(Δ)⌉ + 1 gives exactly the number of bits needed to represent values in [0, Δ]. |
| 2 | The minimum p required by Theorem 1. This is derived from ∏_{k=1}^{K} (1-p)/p ≤ e^ε, solving for p. Lower ε forces higher p (more flipping = stronger privacy). |
| 3 | HMAC with secret key Y generates a deterministic but pseudorandom fingerprint. Different ID_internal values yield different fingerprints. MD5 is used for L=128 bits. |
| 4 | Start with a copy; we will modify it in-place. |
| 5 | Enumerate all K LSBs of all T attributes for all N rows. This is the universe of potentially fingerprintable positions. |
| 6 | The seed encodes the exact position (i, t, k) plus the secret key Y. The primary key r^i.PrimaryKey ensures that the same row is handled consistently even if row order changes. |
| 7 | Selection probability is approximately 2p (probability that U₁(s) mod ⌊1/(2p)⌋ = 0 is approximately 2p). Only ~2p fraction of all K·N·T bits are fingerprinted. |
| 8 | x is the mask bit, uniformly random. It is generated pseudodeterministically from seed s. |
| 9 | Uniformly assigns the bit position to one of the L fingerprint bits. This ensures each fingerprint bit f[l] is embedded approximately m/L times across the database (where m = total selected positions). |
| 10 | B = x XOR f[l]. When x=0: B = f[l]. When x=1: B = NOT f[l]. Since x is uniform, B is also Bernoulli(p) as required by Theorem 1 for the privacy guarantee to hold. |
| 11 | XOR flips the bit if B=1, leaves it unchanged if B=0. The new bit is r^i_{t,k} XOR B. |
| 12 | M(R) is the fingerprinted database; f is stored securely by the owner for later detection. |

### Why B = x XOR f[l] satisfies Bernoulli(p)

From the paper's footnote 3:
- Pr(B=1) = p: the bit is fingerprinted AND changed (XORed by 1)
- Pr(B=0) = p: the bit is fingerprinted but NOT changed (XORed by 0)
- Pr(not selected) = 1 - 2p

The design difference from prior work: previous schemes set the new bit to x XOR f[l] directly (replacing the original), making the fingerprinted result *independent* of the original. This paper uses r^i_{t,k} XOR B, making the result *dependent* on the original, which enables the DP privacy proof.

---

## Part 3 — Algorithm 2: Fingerprint Extraction

**Purpose:** Given a leaked database R̄ and the original database R, extract the embedded fingerprint to identify the guilty SP.

**Inputs:**
- R̄: leaked (potentially distorted) database
- R: original database  
- Y: secret key
- List of {ID_internal_j, f_j} for all SPs

**Output:**
- f̂: extracted fingerprint bit-string
- Identity of the accused SP

### Pseudocode (reconstructed from paper Section IV-C)

```
Algorithm 2: Fingerprint Extraction

INPUT: R̄, R, Y, p, K, L
OUTPUT: f̂ (extracted fingerprint)

Line 1:  Initialize fingerprint template:
           f̂ = [?, ?, ..., ?]  (length L, all unknown)

Line 2:  Initialize counting arrays:
           c₀ = [0, 0, ..., 0]  (length L)
           c₁ = [0, 0, ..., 0]  (length L)

Line 3:  Construct fingerprintable set P̄ from R̄:
           P̄ = { r̄^i_{t,k} | i ∈ [1, N̄], t ∈ [1,T], k ∈ [1, min(K, K_t)] }
           # N̄ = number of records in R̄ (may be < N due to subset attack)

Line 4:  For each bit position r̄^i_{t,k} in P̄:
           # Only process records present in both R̄ and R (matched by primary key)

Line 5:    Recompute seed: s = Y || r^i.PrimaryKey || t || k
           # Use PRIMARY KEY from R̄ to look up the original record in R

Line 6:    Check if this position was selected for fingerprinting:
           if U₁(s) mod ⌊1/(2p)⌋ == 0:

Line 7:      Recover mask bit: x = 0 if U₂(s) even, else x = 1
             Recover fingerprint index: l = U₃(s) mod L

Line 8:      Recover mark bit from leaked database:
             B = r̄^i_{t,k} XOR r^i_{t,k}
             # Compare leaked bit with original bit

Line 9:      Recover fingerprint bit at index l:
             f_l = x XOR B

Line 10:     Update counters:
             if f_l == 0: c₀[l] += 1
             if f_l == 1: c₁[l] += 1

Line 11: Apply majority voting to determine each fingerprint bit:
          for l in [0, L-1]:
            f̂[l] = 1  if c₁[l] > c₀[l]
            f̂[l] = 0  otherwise

Line 12: Compare f̂ with stored fingerprints {f_j}:
          for each SP j:
            D_j = #{l : f̂[l] == f_j[l]}
          Accuse SP j* = argmax_j(D_j) if D_{j*} > D_threshold
```

### Line-by-Line Explanation

| Line | Explanation |
|------|-------------|
| 1 | Template initialized as unknown. Will be filled by majority voting from evidence across all fingerprinted positions. |
| 2 | Two counters per fingerprint bit position. Track how many times that bit was decoded as 0 vs 1. |
| 3 | The leaked database may have fewer records (subset attack) or modified bits. N̄ ≤ N. |
| 4-5 | Iterate over records in R̄. Use the primary key (unchanged in R̄, since primary keys are immutable) to look up the corresponding original record in R. |
| 6 | Reproduce the exact same selection logic as Algorithm 1. Same seed → same U₁(s) → same selection decision. |
| 7 | Reproduce x and l deterministically. Same owner key Y = same results. |
| 8 | If the leaked bit equals the original bit, B=0 (no change or attack reverted). If different, B=1 (bit was flipped). |
| 9 | Reverse the operation: f_l = x XOR B. If the attacker didn't disturb this position, this recovers the original fingerprint bit. |
| 10 | Accumulate evidence across all positions that encode bit l. |
| 11 | Majority voting: if more than half of all positions encoding bit l recovered as 1, then f̂[l] = 1. This is robust against random flipping attacks (if less than 50% of bits are flipped). |
| 12 | Fingerprint matching. A threshold D > L/2 is used. The threshold D is set based on C (number of SPs) to ensure uniqueness. |

### Why majority voting works against random flipping

Each fingerprint bit f_l is embedded w_l ≈ m/L times. The random flipping attack flips each selected bit with probability γ_rnd. For correct recovery we need fewer than w_l/2 of the m/L positions to be flipped. By the Law of Large Numbers, this holds with high probability when w_l is large (many redundant embeddings) and γ_rnd < 0.5.

---

## Part 4 — Algorithm 3: Determine Internal ID for One SP (SVT Intermediate Step)

**Purpose:** For a new SP, find an ID_internal such that the resulting fingerprinted database has sufficient fingerprint density (‖M(R)-R‖_{1,1} > Γ), while maintaining entry-level DP for this determination process.

**Inputs:**
- R: original database
- Y: secret key
- K_c: a hash key specific to the c-th SP (derived from owner's key)
- Γ: fingerprint density threshold
- ε, ε₂, ε₃: privacy budgets
- Δ: sensitivity

**Output:**
- ID_internal_c: accepted internal ID
- ⊤ (TRUE) signal indicating acceptance

### Pseudocode

```
Algorithm 3: DetermineInternalIDforOneSP

INPUT: R, Y, K_c, Γ, ε, ε₂, ε₃, Δ
OUTPUT: ID_internal_c

Line 1:  Initialize trial counter: i = 1

Line 2:  Loop:
           Generate candidate internal ID:
           ID_internal_c = Hash(K_c, i)
           # Hash of (SP-specific key, trial number)

Line 3:    Generate fingerprinted database using candidate ID:
           M^i_c(R) = Algorithm1(R, Y, ID_internal_c, ε, Δ)
           # Note: this M(R) is NOT shared yet, just computed for density check

Line 4:    Compute fingerprint density:
           density = ‖M^i_c(R) - R‖_{1,1}

Line 5:    Draw noise samples:
           μ_i ~ Lap(Δ / ε₂)   # noise for density
           ρ_i ~ Lap(Δ / ε₃)   # noise for threshold

Line 6:    Noisy comparison:
           if density + μ_i > Γ + ρ_i:
             Output ⊤ (TRUE)
             Record ID_internal_c as the accepted ID
             STOP → return ID_internal_c

Line 7:    else:
             Output ⊥ (FALSE)
             i = i + 1
             Continue loop
```

### Line-by-Line Explanation

| Line | Explanation |
|------|-------------|
| 1 | Start from trial 1. The trial counter i is used to generate different candidate IDs. |
| 2 | `Hash(K_c, i)` generates a deterministic but varied internal ID for each trial. K_c is derived from the owner's master key and the SP's external ID. The exact hash function is not specified in the paper (implementation decision). |
| 3 | Run the full Algorithm 1 to get a fingerprinted copy with this candidate ID. This is a *tentative* copy — it will be shared only if it passes the density check. Privacy cost of this step does NOT count toward the total (it's the comparison that costs privacy, not the generation). |
| 4 | Compute ‖M^i_c(R) - R‖_{1,1}: sum of absolute differences across all entries. This measures how many bits were changed and by how much. |
| 5 | Add Laplace noise to both sides of the comparison. ε₂ controls accuracy of density estimate, ε₃ controls accuracy of threshold. Both calibrated to sensitivity Δ. |
| 6 | If the noisy comparison holds, accept this ID. The SVT only charges privacy budget for this acceptance event (not the failed trials). The ID is kept private; only the fingerprinted database is shared. |
| 7 | If rejected, try the next ID. In practice, this converges in 1-2 trials (experimentally observed). |

### Privacy Guarantee (Theorem 3)

Algorithm 3 achieves **(ε₂ + ε₃)-entry-level DP** for the determination of ID_internal.

The fingerprinted database generation in Line 3 uses privacy budget ε but does NOT contribute to the total privacy loss, because the numerical M(R) is not yet shared.

---

## Part 5 — Algorithm 4: Release Multiple Fingerprinted Databases

**Purpose:** Compose Algorithm 3 for C SPs, actually releasing each fingerprinted database after a successful ID determination. Controls cumulative privacy loss across all C sharings via advanced composition.

**Inputs:** Same as Algorithm 3, plus C (maximum number of SPs)

**Output:** For each SP c ∈ [1,C]: share M_c(R) with SP_c

### Pseudocode

```
Algorithm 4: ReleaseMultipleFingerprinted Databases

INPUT: R, Y, {K_c}_{c=1}^C, Γ, ε, ε₂, ε₃, Δ, C
OUTPUT: {M_c(R)}_{c=1}^C shared with respective SPs

Line 1:  For c = 1 to C:

Line 2:    [INTERMEDIATE STEP] Run Algorithm 3 to determine ID_internal_c:
           ID_internal_c = DetermineInternalIDforOneSP(
               R, Y, K_c, Γ, ε, ε₂, ε₃, Δ)

Line 3:    [KEY DIFFERENCE FROM ALG. 3] Share the fingerprinted database:
           M_c(R) = Algorithm1(R, Y, ID_internal_c, ε, Δ)
           Send M_c(R) to SP_c
           # NOW this generation costs privacy budget ε

Line 4:    Store (c, ID_internal_c, f_c) in owner's secure records
           # For future fingerprint extraction and traitor identification
```

### Differences from Algorithm 3

| Aspect | Algorithm 3 | Algorithm 4 |
|--------|-------------|-------------|
| Generates M(R) | Yes, but only for density check | Yes, and SHARES it with SP |
| Loops over trials | Yes, until density > Γ | Yes (inherits from Alg. 3) |
| Loops over SPs | No (single SP) | Yes, for c = 1 to C |
| Privacy cost of sharing | Not charged (not shared yet) | **Charged**: ε per sharing |
| Privacy cost of ID determination | ε₂ + ε₃ per SP (Theorem 3) | ε₂ + ε₃ per SP (Theorem 3) |

### Privacy Guarantee (Theorem 4)

Algorithm 4 achieves **(ε₀, δ₀)-entry-level DP** where:

```
ε₀ = 2C·ln(1/δ')·(ε + ε₂ + ε₃) + C·ε·(e^ε - 1) + C·(ε₂+ε₃)·(e^(ε₂+ε₃) - 1)
δ₀ = 2δ'
```

This uses the **Advanced Composition Theorem** (Dwork & Roth 2014), which gives O(√C) growth in privacy cost instead of the naive O(C) linear growth.

---

## Part 6 — Implementation Gaps: Details Not Fully Specified in the Paper

These are necessary implementation decisions that the paper leaves open or underspecified.

### Gap 1: Seed Format and Encoding

**Paper says:** `s = Y | r^i.PrimaryKey | t | k`  
`|` is the concatenation operator.

**Not specified:**
- Exact byte encoding of each field (little-endian? big-endian? fixed-width?)
- How to handle string vs. integer primary keys
- Whether t and k are encoded as 1 byte, 2 bytes, 4 bytes
- Whether a separator byte is needed between fields to avoid ambiguity

**Recommended implementation:**
```python
s = sha256(Y + struct.pack(">Q", primary_key) + struct.pack(">H", t) + struct.pack(">H", k))
```
Or use HMAC directly:
```python
s = HMAC(key=Y, msg=str(primary_key).encode() + t.to_bytes(2,'big') + k.to_bytes(2,'big'))
```

**Critical requirement:** The encoding must be **deterministic** and **collision-free** so that different (i, t, k) always produce different seeds.

---

### Gap 2: Pseudorandom Generator U — Three Separate Calls

**Paper says:** U is a cryptographic PRNG; U₁(s), U₂(s), U₃(s) are the 1st, 2nd, 3rd outputs.

**Not specified:**
- Whether U is a stream cipher (e.g., ChaCha20), a hash-based CTR (e.g., AES-CTR), or a simpler PRNG
- The exact byte width of each output
- Whether U₁, U₂, U₃ share the exact same seed or use derived sub-seeds

**Recommended implementation:**
```python
# Use a stream cipher or CTR mode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def get_u123(seed_bytes):
    # Use AES-CTR as PRNG
    cipher = Cipher(algorithms.AES(seed_bytes[:16]), modes.CTR(b'\x00'*16))
    enc = cipher.encryptor()
    stream = enc.update(b'\x00' * 16)  # generate 128 bits = 16 bytes
    U1 = int.from_bytes(stream[0:4], 'big')   # 32-bit integer
    U2 = int.from_bytes(stream[4:8], 'big')   # 32-bit integer
    U3 = int.from_bytes(stream[8:12], 'big')  # 32-bit integer
    return U1, U2, U3
```

Or alternatively use a KDF and index-based generation:
```python
U1 = int(hmac_sha256(s, b'\x00'))
U2 = int(hmac_sha256(s, b'\x01'))
U3 = int(hmac_sha256(s, b'\x02'))
```

---

### Gap 3: HMAC Input Format for Fingerprint Generation

**Paper says:** `f = HMAC_Y(ID_internal)` with MD5 as the hash.

**Not specified:**
- Whether Y is the HMAC key and ID_internal is the message, or vice versa
- The encoding of ID_internal (bytes? string? fixed-length?)
- Whether the result is truncated or padded to L = 128 bits

**Recommended:**
```python
import hmac, hashlib

f = hmac.new(key=Y, msg=ID_internal.encode('utf-8'), digestmod=hashlib.md5).digest()
# f is 16 bytes = 128 bits = L fingerprint bits
# Access bit l: (f[l // 8] >> (7 - (l % 8))) & 1
```

---

### Gap 4: ID_internal Generation — Hash(K_c, i)

**Paper says:** `ID_internal_c = Hash(K_c, i)` where i is the trial number.

**Not specified:**
- The hash function to use
- How K_c is derived from Y and SP's external ID
- The encoding of (K_c, i) for the hash input

**Suggested implementation:**
```python
# Derive SP-specific key K_c from master key and external ID
K_c = HMAC(key=Y, msg=("SP_KEY_" + str(ID_external)).encode())

# Generate internal ID for c-th SP, i-th trial
ID_internal = HMAC(key=K_c, msg=i.to_bytes(4, 'big'))
```

---

### Gap 5: Attribute Selection — Which Attributes to Fingerprint

**Paper says:** All T attributes are in the fingerprintable set P, excluding the primary key. For each attribute t, use min(K, K_t) LSBs.

**Not specified:**
- How to handle label/class attributes (paper mentions not fingerprinting labels in experiments)
- How to handle attributes with domain-clipping requirements
- How K_t is determined for each attribute (max bits needed for the attribute's domain)
- Treatment of NULL values or missing data

**Implementation logic:**
```python
def build_fingerprintable_set(R, K, excluded_attrs=None):
    P = []
    for i, row in enumerate(R):
        for t, value in enumerate(row):
            if t in excluded_attrs:
                continue
            K_t = value.bit_length()  # or predefined per attribute
            for k in range(1, min(K, K_t) + 1):
                P.append((i, t, k))
    return P
```

---

### Gap 6: Tuple (Row) Selection Logic

**Paper says:** Each bit position r^i_{t,k} is independently selected via `U₁(s) mod ⌊1/(2p)⌋ == 0`.

**Not specified:**
- Whether rows are selected as a whole, or bit-by-bit independently
- The paper's mechanism selects **individual bits** independently, NOT rows

**Clarification from the paper:**
The selection is per-bit, not per-row. For each (i, t, k) triple, independently decide if it is fingerprinted. This means a single row may have 0, 1, 2, or more bits fingerprinted.

**Implementation:**
```python
selection_threshold = int(1 / (2 * p))
for (i, t, k) in P:
    s = compute_seed(Y, primary_key[i], t, k)
    U1, U2, U3 = get_u123(s)
    if U1 % selection_threshold == 0:   # selected
        x = 0 if U2 % 2 == 0 else 1
        l = U3 % L
        B = x ^ fingerprint[l]
        database[i][t] = flip_bit_k(database[i][t], k, B)
```

---

### Gap 7: Majority Voting Rule

**Paper says:** f̂[l] = 1 if c₁[l] > c₀[l], else f̂[l] = 0.

**Not specified:**
- What to do when c₁[l] == c₀[l] (tie)
- What to do when c₀[l] + c₁[l] == 0 (no evidence for bit l, e.g., due to severe subset attack)

**Recommended handling:**
```python
for l in range(L):
    if c1[l] + c0[l] == 0:
        f_hat[l] = 0  # default; or mark as unknown
    elif c1[l] > c0[l]:
        f_hat[l] = 1
    else:
        f_hat[l] = 0  # tie counts as 0
```

---

### Gap 8: p vs. 2p — Selection Probability vs. Flip Probability

This is a **critical distinction** explicitly clarified in footnote 3 of the paper:

- **p** = probability that mark bit B = 1 (bit is changed)
- **p** = probability that mark bit B = 0 (bit is fingerprinted but not changed)
- **2p** = total probability that a bit is *selected* for fingerprinting (may or may not be changed)
- **1 - 2p** = probability that a bit is NOT selected

When implementing the selection condition:
```python
# WRONG: confusing p with 2p
if U1(s) % (1/p) == 0:

# CORRECT: selection probability is 2p
selection_period = int(1 / (2*p))
if U1(s) % selection_period == 0:   # probability ≈ 2p
```

---

### Gap 9: Post-Processing Domain Clipping

**Paper says:** Post-process M(R) to remove entries outside the valid domain. 

**Not specified:**
- The exact clipping rule (clip to domain max/min? round? reassign to nearest valid value?)
- Whether clipping happens before or after all bits are processed

**Recommended:**
```python
def post_process(value, domain_min, domain_max):
    return max(domain_min, min(domain_max, value))
```

Post-processing is safe due to DP's post-processing immunity — privacy guarantees are preserved.

---

### Gap 10: Fingerprint Density Threshold Γ

**Paper says** (Section VII-C): `Γ = (1/2 + 1/√12) · Δ · p · N · K`

The justification: model ‖M(R) - R‖_{1,1} as Uniform[0, Δ·p·N·T], then mean + one standard deviation gives the threshold.

**Not specified:**
- Whether T or K should be used in the formula (paper uses both interchangeably in this section; the experimental formula appears to use K, not T)
- How to tune Γ for different database sizes and attribute counts

**From experimental setup:**
```
Γ = (0.5 + 1/√12) · Δ · p · N · K
  ≈ 0.789 · Δ · p · N · K
```

---

## Part 7 — Summary of All Four Algorithms

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  ALGORITHM 1: Fingerprint Insertion                                           │
│  Purpose:  Embed unique fingerprint into database for one SP                  │
│  Input:    R, Y, ID_internal, ε, Δ                                           │
│  Output:   M(R)  [fingerprinted database]                                    │
│  Privacy:  ε-entry-level DP  (Theorem 2)                                     │
│  Key ops:  HMAC, PRNG (U₁U₂U₃), XOR                                         │
└──────────────────────────────────────────────────────────────────────────────┘
         ↓ invoked by
┌──────────────────────────────────────────────────────────────────────────────┐
│  ALGORITHM 3: Determine Internal ID for One SP  (SVT Intermediate Step)      │
│  Purpose:  Find ID_internal s.t. fingerprint density > Γ (noisy comparison) │
│  Input:    R, Y, K_c, Γ, ε, ε₂, ε₃, Δ                                      │
│  Output:   ID_internal_c  [kept secret from SP]                              │
│  Privacy:  (ε₂+ε₃)-entry-level DP  (Theorem 3)                              │
│  Key ops:  Alg.1, Laplace noise, noisy threshold comparison                  │
└──────────────────────────────────────────────────────────────────────────────┘
         ↓ composed C times by
┌──────────────────────────────────────────────────────────────────────────────┐
│  ALGORITHM 4: Release Multiple Fingerprinted Databases                       │
│  Purpose:  Share fingerprinted copies with C SPs, control cumulative privacy │
│  Input:    R, Y, {K_c}, Γ, ε, ε₂, ε₃, Δ, C                                │
│  Output:   {M_c(R)} shared with respective SPs                               │
│  Privacy:  (ε₀, δ₀)-entry-level DP  (Theorem 4)                             │
│  Key ops:  C × Alg.3, C × Alg.1, Advanced Composition Theorem               │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│  ALGORITHM 2: Fingerprint Extraction  (used for traitor detection)           │
│  Purpose:  Recover fingerprint from leaked database R̄                        │
│  Input:    R̄, R, Y, p, K, L                                                  │
│  Output:   f̂  [extracted fingerprint bit-string]                             │
│  Privacy:  N/A (post-hoc analysis)                                           │
│  Key ops:  Majority voting on c₀[l], c₁[l] counters                         │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Part 8 — Key Formulas Reference Card

| Formula | Meaning |
|---------|---------|
| `K = ⌈log₂(Δ)⌉ + 1` | Number of LSBs to fingerprint |
| `p ≥ 1/(e^(ε/K) + 1)` | Minimum flip probability for ε-entry-level DP |
| `s = Y \|\| PK \|\| t \|\| k` | Deterministic seed per bit position |
| `f = HMAC_Y(ID_internal)` | Fingerprint bit-string generation |
| `B = x XOR f[l]` | Mark bit (x ~ Uniform{0,1}, f[l] is fingerprint bit) |
| `r^i_{t,k} ← r^i_{t,k} XOR B` | Bit modification |
| `B_recovery = r̄^i_{t,k} XOR r^i_{t,k}` | Recover mark bit during extraction |
| `f_l = x XOR B_recovery` | Recover fingerprint bit |
| `f̂[l] = 1 iff c₁[l] > c₀[l]` | Majority vote decision |
| `E[‖M(R)-R‖_{1,1}] ∈ [0, Δ·p·N·T]` | Fingerprint density bound (Corollary 1) |
| `InfCap ≤ ψ·e^ε/(ψ·e^ε+1)` | Inference capability bound under ε-entry-level DP |
| `ε₀ = 2C·ln(1/δ')·(ε+ε₂+ε₃) + C·ε·(e^ε-1) + C·(ε₂+ε₃)·(e^(ε₂+ε₃)-1)` | Total privacy budget for C sharings |
