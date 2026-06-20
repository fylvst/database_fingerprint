# Architecture: Privacy-Preserving Database Fingerprinting (NDSS 2023)

> Paper: *Privacy-Preserving Database Fingerprinting*, Ji et al., NDSS 2023  
> DOI: 10.14722/ndss.2023.24693

---

## 1. High-Level System Overview

This paper proposes a **unified** mechanism that simultaneously achieves:

| Goal | Mechanism |
|------|-----------|
| **Privacy** | ε-entry-level Differential Privacy (DP) via bit-level random response |
| **Liability** | Database fingerprinting (unique per-SP bit-string embedded in insignificant bits) |
| **Utility** | Only the K least-significant bits (LSBs) of selected entries are changed |

The key insight is that the randomness introduced by fingerprinting is **transformed** into a provable privacy guarantee — privacy comes "for free" during fingerprint insertion.

---

## 2. System Participants

| Entity | Role |
|--------|------|
| **Database Owner** | Holds original database R, secret key Y, generates and embeds fingerprints, detects traitors |
| **SP_j (Service Provider j)** | Receives fingerprinted copy R_j; may be honest, attacker, or curious |
| **Traitor (malicious SP)** | Leaks or redistributes its fingerprinted copy R̄ |

---

## 3. Complete Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DATABASE OWNER                                       │
│                                                                               │
│  Original Database R                                                          │
│  Secret Key Y                                                                 │
│  External ID of SP_j  ──────────────────────────────────────────────────────►│
│                        │                                                      │
│              ┌─────────▼──────────┐                                          │
│              │  ID Generation     │  (Algorithm 3 / Algorithm 4)             │
│              │  ID_internal =     │  Hash(K_c, i)  where i = trial number    │
│              │  Hash(K_c, i)      │                                          │
│              └─────────┬──────────┘                                          │
│                        │ ID_internal                                          │
│              ┌─────────▼──────────────────────────────────────────┐         │
│              │         FINGERPRINT GENERATION  (Section IV-B)     │         │
│              │                                                     │         │
│              │  f = HMAC_Y( ID_internal )                          │         │
│              │  Length L = 128 bits (MD5)                          │         │
│              └─────────┬───────────────────────────────────────────┘         │
│                        │ fingerprint bit-string f                             │
│              ┌─────────▼───────────────────────────────────────────┐         │
│              │         FINGERPRINT INSERTION  (Algorithm 1)        │         │
│              │                                                     │         │
│              │  For each bit position r^i_{t,k} in P:              │         │
│              │    seed s = Y | r^i.PrimaryKey | t | k              │         │
│              │    if U1(s) mod ⌊1/2p⌋ == 0 → select this bit      │         │
│              │      x  = (U2(s) is even) ? 0 : 1                  │         │
│              │      l  = U3(s) mod L                               │         │
│              │      B  = x XOR f[l]                                │         │
│              │      r^i_{t,k} ← r^i_{t,k} XOR B                   │         │
│              └─────────┬───────────────────────────────────────────┘         │
│                        │                                                      │
│              ┌─────────▼───────────────────────────────────────────┐         │
│              │   Fingerprint Density Check  (SVT, Algorithm 3/4)  │         │
│              │                                                     │         │
│              │  if ‖M(R) - R‖_{1,1} + μ > Γ + ρ  → ACCEPT        │         │
│              │  else increment i, regenerate ID_internal, retry    │         │
│              └─────────┬───────────────────────────────────────────┘         │
└───────────────────────┼────────────────────────────────────────────────────┘
                        │  Fingerprinted Database  M(R) = R_j
                        ▼
             ┌─────────────────────┐
             │     SP_j            │  receives R_j (= M(R))
             │  (Service Provider) │
             └─────────┬───────────┘
                       │
            [malicious SP leaks database]
                       │
                       ▼
             ┌─────────────────────┐
             │  Leaked Database R̄  │  (may be distorted: random flip,
             └─────────┬───────────┘   subset attack, correlation attack)
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                   FINGERPRINT EXTRACTION  (Algorithm 2)                       │
│                                                                               │
│  Owner reconstructs fingerprintable set P̄ from R̄                            │
│  For each bit position, recompute seed s = Y | r^i.PrimaryKey | t | k        │
│  Recover mark bit:   B = r̄^i_{t,k} XOR r^i_{t,k}                            │
│  Recover fp bit:    f_l = x XOR B                                             │
│  Maintain counters c0[l] and c1[l]                                            │
│  Final decision:    f[l] = 1 if c1[l] > c0[l], else 0  (majority vote)       │
└──────────────────────────────────────────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                   TRAITOR IDENTIFICATION                                       │
│                                                                               │
│  Compare extracted fingerprint f̂ with each SP_j's stored fingerprint f_j    │
│  Count bit matches: D = #{l : f̂[l] == f_j[l]}                               │
│  SP_j is declared GUILTY if D exceeds threshold (> 50% overlap empirically)  │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Four Core Algorithms — Relationships

```
Algorithm 1: Fingerprint Insertion (single SP)
     ↑ called by
Algorithm 3: Determine Internal ID for One SP (SVT intermediate step)
     ↑ composed C times by
Algorithm 4: Share Multiple Fingerprinted Databases (full SVT pipeline)

Algorithm 2: Fingerprint Extraction (used during detection)
     ↑ independent, triggered when a leaked database is found
```

---

## 5. Mathematical Symbol Reference Table

| Symbol | Type | Meaning |
|--------|------|---------|
| **R** | Matrix | Original relational database (N rows × T attributes) |
| **R'** | Matrix | Neighboring database of R (differs by exactly one entry) |
| **M(R)** | Matrix | Fingerprinted database output by Algorithm 1 |
| **R̄** | Matrix | Leaked (pirated) database recovered by database owner |
| **ε** | Scalar (>0) | Privacy budget for ε-entry-level DP. Smaller ε = stronger privacy |
| **ε₀** | Scalar | Cumulative privacy budget across C sharings (Algorithm 4) |
| **ε₂** | Scalar | Privacy budget for the density comparison noise μ (Laplace noise) |
| **ε₃** | Scalar | Privacy budget for the threshold comparison noise ρ (Laplace noise) |
| **δ** | Scalar ∈(0,1) | Slack in (ε,δ)-DP formulation |
| **δ₀** | Scalar | Cumulative δ across C sharings |
| **Δ** | Scalar | Database sensitivity = sup_{R,R'} ‖R - R'‖_F over neighboring pairs. Equals the max pairwise entry difference |
| **K** | Integer | Number of least-significant bits fingerprinted per entry. K = ⌈log₂(Δ)⌉ + 1 |
| **K_t** | Integer | Number of bits used to encode the t-th attribute |
| **p** | Scalar ∈(0, 0.5) | Probability that a specific bit is changed (i.e., B = 1). Also: probability B = 0. Selection probability = 2p |
| **B** | Binary r.v. | Mark bit. B ~ Bernoulli(p). The actual XOR mask applied to the selected bit |
| **x** | Binary | Mask bit derived from pseudorandom generator U₂(s). x ∈ {0, 1} with equal probability |
| **f** | Bit-string | Fingerprint bit-string for a specific SP. f = HMAC_Y(ID_internal). Length = L bits |
| **f_l** | Bit | The l-th bit of fingerprint string f |
| **L** | Integer | Length of fingerprint string. L = 128 (MD5) is used |
| **Y** | Key | Secret cryptographic key of the database owner |
| **ID_external** | String | Publicly known identifier of the SP |
| **ID_internal** | String | Internal identifier generated by owner. Used as HMAC input |
| **U** | PRNG | Cryptographic pseudorandom sequence generator. U₁, U₂, U₃ are calls with the same seed |
| **s** | Seed | Pseudorandom seed s = Y \| r^i.PrimaryKey \| t \| k |
| **P** | Set | Set of all fingerprintable bit positions P = {r^i_{t,k} \| i∈[N], t∈[T], k∈[1, min(K, K_t)]} |
| **P̄** | Set | Fingerprintable bit set reconstructed from leaked database R̄ |
| **N** | Integer | Number of data records (rows) in R |
| **T** | Integer | Number of attributes (columns) in R |
| **r^i** | Row vector | The i-th data record in R |
| **r^i_{t,k}** | Bit | k-th least significant bit of the t-th attribute of r^i |
| **r^i.PrimaryKey** | Key | Immutable primary key of record i |
| **c₀[l], c₁[l]** | Integer arrays | Counters: number of times bit l is recovered as 0 or 1 during extraction |
| **D** | Integer (≤L) | Threshold for number of bit matches required to accuse an SP |
| **C** | Integer | Maximum number of SPs the database is shared with |
| **Γ** | Scalar | Fingerprint density threshold. M(R) accepted only if ‖M(R)-R‖_{1,1} > Γ |
| **μ_i** | Laplace r.v. | Noise added to fingerprint density. μ_i ~ Lap(Δ/ε₂) |
| **ρ_i** | Laplace r.v. | Noise added to threshold Γ. ρ_i ~ Lap(Δ/ε₃) |
| **γ_rnd** | Scalar | Bit-flip probability in the random bit flipping attack |
| **γ_sub** | Scalar | Row-inclusion probability in the subset attack |
| **G** | Scalar | Confidence gain of malicious SP under correlation attack |
| **w_l** | Integer | Number of times the l-th fingerprint bit is embedded in the database |
| **m** | Integer | Total number of fingerprinted bit positions across database |
| **Hash(K_c, i)** | Function | Hash used to generate ID_internal for c-th SP at i-th trial |
| **HMAC_Y(·)** | Function | HMAC with owner's secret key Y. Output = fingerprint bit-string f |

---

## 6. Privacy Model: ε-Entry-Level DP

**Definition (standard DP):** hides presence/absence of a *row*.  
**This paper's model:** hides the *value of a single attribute entry* (not a row).

Formally:
```
Pr[M(R) = S] ≤ e^ε · Pr[M(R') = S]   for all neighboring R, R' and all S
```
where R and R' are **neighboring** if they differ by exactly **one attribute value** of one row.

This is appropriate because primary keys are public and immutable in DBMS — row membership is not secret.

---

## 7. Key Theorem (Theorem 1) — Privacy Condition

> A bit-level random response scheme satisfies **ε-entry-level DP** if and only if:
> - K = ⌈log₂(Δ)⌉ + 1  (number of LSBs to fingerprint)
> - p ≥ 1 / (e^(ε/K) + 1)  (minimum flip probability)

Intuition: flipping K bits with probability p can "blur" the maximum difference Δ between any two neighboring entries.

---

## 8. Three-Way Trade-Off (Figure 3 in Paper)

```
                    ↑ Stronger privacy (smaller ε)
                    │
    p must          │         ← requires higher p
    increase ───────┼──────── → higher fingerprint robustness
                    │
                    │         ← but higher p means more bit changes
                    ↓ Lower database utility (larger expected error)
```

The relationship is:
- **Higher p** → stronger fingerprint robustness + stronger privacy guarantee
- **Higher p** → larger expected entry distortion (lower utility)
- **Smaller ε** → requires higher p → higher robustness but lower utility
- All three dimensions are formally quantified in Section V.

---

## 9. SVT-Based Multiple Sharing (Algorithms 3 & 4)

Problem: sharing the same database C times causes cumulative privacy loss that grows linearly.

Solution: Use **Sparse Vector Technique (SVT)**:

1. For each new SP, keep generating new `ID_internal` until:
   ```
   ‖M(R) - R‖_{1,1} + μ_i  >  Γ + ρ_i
   ```
   where μ_i ~ Lap(Δ/ε₂), ρ_i ~ Lap(Δ/ε₃)

2. The SVT only charges privacy budget for queries that satisfy the threshold ("TRUE"), not for the repeated trials that fail.

3. Privacy budget allocation: set ε₂ = ε₃ = ε*/2 to minimize variance of the noisy comparison.

4. Total privacy guarantee (Theorem 4):
   ```
   ε₀ = 2C·ln(1/δ')·(ε + ε₂ + ε₃) + C·ε·(e^ε - 1) + C·(ε₂+ε₃)·(e^(ε₂+ε₃) - 1)
   δ₀ = 2δ'
   ```

---

## 10. Attack Models Covered

| Attack | Description | Defense mechanism |
|--------|-------------|-------------------|
| **Random Bit Flipping** | Malicious SP flips each of the K LSBs with probability γ_rnd | Majority voting in extraction; higher p increases P_rbst_rnd |
| **Subset Attack** | Malicious SP includes each row with probability γ_sub in pirated copy | As long as not all rows for any fingerprint bit are removed, detection succeeds |
| **Correlation Attack** | SP exploits statistical correlations between attributes to identify and flip fingerprinted bits | Higher p reduces confidence gain G; post-processing via [26] can further mitigate |
| **Attribute Inference Attack** | SP uses all other entries to infer the original value of one entry | Entry-level DP bounds inference capability: InfCap ≤ ψ·e^ε / (ψ·e^ε + 1) |
| **Average Attack (Multiple Sharing)** | Average of multiple copies converges to original R | SVT-based composition controls cumulative privacy loss |

---

## 11. Post-Processing Note

After fingerprinting, some entries may fall outside the valid domain (e.g., value "5" when max is "4"). Post-processing clips these to domain values. This does NOT degrade privacy (post-processing immunity of DP) and has negligible impact on fingerprint robustness (majority voting absorbs small perturbations).
