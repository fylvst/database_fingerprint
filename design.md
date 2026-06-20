# Software Architecture Design
## Privacy-Preserving Database Fingerprinting (NDSS 2023) — C++ Implementation

> Based on: `architecture.md` + `algorithm_analysis.md`  
> Language: C++17  
> Build System: CMake 3.20+  
> Dependencies: OpenSSL (HMAC/MD5), Eigen3 (matrix ops, optional)

---

## Table of Contents

1. [Directory Structure](#1-directory-structure)
2. [Overall Architecture Diagram](#2-overall-architecture-diagram)
3. [Core Data Structures](#3-core-data-structures)
4. [Module: FingerprintGenerator](#4-module-fingerprintgenerator)
5. [Module: FingerprintInserter](#5-module-fingerprintinserter)
6. [Module: FingerprintExtractor](#6-module-fingerprintextractor)
7. [Module: FingerprintDetector](#7-module-fingerprintdetector)
8. [Module: PrivacyBudgetManager](#8-module-privacybudgetmanager)
9. [Module: AttackSimulator](#9-module-attacksimulator)
10. [Module: DatasetLoader](#10-module-datasetloader)
11. [Module: ExperimentRunner](#11-module-experimentrunner)
12. [Inter-Module Data Flow](#12-inter-module-data-flow)
13. [Error Handling Strategy](#13-error-handling-strategy)
14. [Build & Dependency Graph](#14-build--dependency-graph)
15. [Time & Space Complexity Summary](#15-time--space-complexity-summary)

---

## 1. Directory Structure

```
database_fingerprint/
├── CMakeLists.txt                    # Root build file
├── README.md
├── design.md                         # This file
├── architecture.md
├── algorithm_analysis.md
│
├── src/
│   ├── CMakeLists.txt
│   │
│   ├── fingerprint/                  # Core fingerprinting algorithms
│   │   ├── CMakeLists.txt
│   │   ├── FingerprintGenerator.h    # HMAC-based fingerprint generation
│   │   ├── FingerprintGenerator.cpp
│   │   ├── FingerprintInserter.h     # Algorithm 1: Insertion
│   │   ├── FingerprintInserter.cpp
│   │   ├── FingerprintExtractor.h    # Algorithm 2: Extraction
│   │   ├── FingerprintExtractor.cpp
│   │   └── FingerprintDetector.h    # Traitor identification
│   │   └── FingerprintDetector.cpp
│   │
│   ├── privacy/                      # DP and SVT mechanisms
│   │   ├── CMakeLists.txt
│   │   ├── PrivacyBudgetManager.h   # Algorithms 3 & 4, SVT
│   │   ├── PrivacyBudgetManager.cpp
│   │   ├── LaplaceNoise.h           # Laplace noise generator
│   │   └── LaplaceNoise.cpp
│   │
│   ├── crypto/                       # Cryptographic primitives
│   │   ├── CMakeLists.txt
│   │   ├── HmacSha256.h             # HMAC-SHA256 wrapper
│   │   ├── HmacSha256.cpp
│   │   ├── PrngCtr.h                # AES-CTR based PRNG (U1/U2/U3)
│   │   └── PrngCtr.cpp
│   │
│   ├── database/                     # Database representation
│   │   ├── CMakeLists.txt
│   │   ├── RelationalDatabase.h     # Core DB type
│   │   ├── RelationalDatabase.cpp
│   │   ├── DatabaseEncoder.h        # Categorical → integer encoding
│   │   └── DatabaseEncoder.cpp
│   │
│   ├── datasets/                     # Dataset loaders
│   │   ├── CMakeLists.txt
│   │   ├── DatasetLoader.h          # Abstract loader interface
│   │   ├── CsvLoader.h              # Generic CSV loader
│   │   ├── CsvLoader.cpp
│   │   ├── NurseryLoader.h          # UCI Nursery dataset
│   │   ├── NurseryLoader.cpp
│   │   ├── CensusLoader.h           # UCI Census dataset
│   │   └── CensusLoader.cpp
│   │
│   ├── attacks/                      # Attack simulators
│   │   ├── CMakeLists.txt
│   │   ├── AttackSimulator.h        # Abstract attack interface
│   │   ├── RandomFlippingAttack.h   # Random bit flipping
│   │   ├── RandomFlippingAttack.cpp
│   │   ├── SubsetAttack.h           # Subset (row removal) attack
│   │   ├── SubsetAttack.cpp
│   │   ├── CorrelationAttack.h      # Correlation-based attack
│   │   └── CorrelationAttack.cpp
│   │
│   └── experiments/                  # Experiment harness
│       ├── CMakeLists.txt
│       ├── ExperimentRunner.h
│       ├── ExperimentRunner.cpp
│       ├── SingleSharingExperiment.h
│       ├── SingleSharingExperiment.cpp
│       ├── MultipleSharingExperiment.h
│       ├── MultipleSharingExperiment.cpp
│       └── MetricsCollector.h       # SVM accuracy, PCA deviation, etc.
│
├── tests/
│   ├── CMakeLists.txt
│   ├── test_fingerprint_generator.cpp
│   ├── test_fingerprint_inserter.cpp
│   ├── test_fingerprint_extractor.cpp
│   ├── test_fingerprint_detector.cpp
│   ├── test_privacy_budget.cpp
│   ├── test_attacks.cpp
│   ├── test_prng.cpp
│   └── test_integration.cpp         # End-to-end pipeline test
│
├── docs/
│   ├── api/                         # Doxygen output (generated)
│   └── notes/
│       ├── implementation_notes.md
│       └── parameter_tuning.md
│
└── data/
    ├── nursery/
    │   └── nursery.data             # UCI Nursery dataset
    └── census/
        └── adult.data               # UCI Census dataset
```

---

## 2. Overall Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Application Layer                                  │
│                                                                               │
│   ExperimentRunner                                                            │
│   ┌──────────────────┐    ┌───────────────────────┐                         │
│   │ SingleSharing    │    │  MultipleSharingExp   │                         │
│   │ Experiment       │    │  (SVT-based)          │                         │
│   └────────┬─────────┘    └──────────┬────────────┘                         │
└────────────┼──────────────────────────┼────────────────────────────────────┘
             │                          │
             ▼                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Core Fingerprinting Layer                            │
│                                                                               │
│  ┌──────────────────┐   ┌──────────────────┐   ┌────────────────────────┐  │
│  │ FingerprintGen   │   │ FingerprintInserter│  │ PrivacyBudgetManager  │  │
│  │ (HMAC → f bits)  │──►│  (Algorithm 1)    │◄─│  (Algorithms 3 & 4)   │  │
│  └──────────────────┘   └────────┬──────────┘  └────────────────────────┘  │
│                                  │                          │                │
│                                  ▼ M(R)                    │ ID_internal     │
│                          ┌───────────────┐                 │                │
│                          │  RelationalDB  │◄────────────────┘                │
│                          │  (fingerprinted│                                  │
│                          │   copy)       │                                  │
│                          └───────┬───────┘                                  │
│                                  │ R̄ (leaked)                               │
│                                  ▼                                          │
│  ┌─────────────────────┐   ┌─────────────────────┐                         │
│  │ FingerprintExtractor│   │ FingerprintDetector  │                         │
│  │  (Algorithm 2)      │──►│ (Traitor Accusation) │                         │
│  └─────────────────────┘   └─────────────────────┘                         │
└─────────────────────────────────────────────────────────────────────────────┘
             │                          │
             ▼                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Support Layer                                         │
│                                                                               │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │  PrngCtr     │  │ HmacSha256  │  │ LaplaceNoise │  │ AttackSimulator  │ │
│  │ (U1/U2/U3)  │  │             │  │              │  │ (Flip/Subset/Corr│ │
│  └──────────────┘  └─────────────┘  └──────────────┘  └──────────────────┘ │
│                                                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                  DatasetLoader / DatabaseEncoder                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Data Structures

### 3.1 `RelationalDatabase`

```cpp
// src/database/RelationalDatabase.h

#pragma once
#include <vector>
#include <string>
#include <cstdint>

/// A single data record: T integer-encoded attribute values.
/// Attributes are 0-indexed; attribute[0] is typically the primary key.
struct Record {
    uint64_t primary_key;              ///< Immutable identifier
    std::vector<int32_t> attributes;   ///< Integer-encoded attribute values
                                       ///< Excludes primary key from fingerprinting
};

/// Domain metadata for one attribute
struct AttributeDomain {
    int32_t min_val;         ///< Minimum integer value
    int32_t max_val;         ///< Maximum integer value
    int32_t num_bits;        ///< K_t = ceil(log2(max_val - min_val + 1))
    std::string name;        ///< Human-readable attribute name
    bool fingerprint;        ///< Whether this attribute is fingerprinted (default: true)
                             ///< Labels/target columns are excluded
};

/// The core database container
class RelationalDatabase {
public:
    std::vector<Record>          records;     ///< N records
    std::vector<AttributeDomain> domains;     ///< T attribute domains
    int32_t sensitivity;                      ///< Δ = max over all attributes of (max_val - min_val)

    // --- Accessors ---
    size_t num_records()    const { return records.size(); }
    size_t num_attributes() const { return domains.size(); }

    /// Get bit k (1-indexed from LSB) of attribute t of record i
    int get_bit(size_t i, size_t t, int k) const;

    /// Set bit k (1-indexed from LSB) of attribute t of record i
    void set_bit(size_t i, size_t t, int k, int bit_value);

    /// Compute fingerprint density: L1,1 norm of (this - other)
    double fingerprint_density(const RelationalDatabase& original) const;

    /// Post-process: clip all values to their valid domain
    void clip_to_domain();
};
```

**Memory:** O(N × T) integers. For N=32561, T=13: ~1.7 MB at int32_t.

---

### 3.2 `Fingerprint`

```cpp
// src/fingerprint/FingerprintGenerator.h  (partial)

/// A 128-bit fingerprint bit-string (L = 128 for MD5 output)
struct Fingerprint {
    static constexpr size_t LENGTH_BITS = 128;
    uint8_t bits[16];   ///< 16 bytes = 128 bits

    int  get_bit(size_t l) const;        ///< l ∈ [0, 127]
    void set_bit(size_t l, int val);
    int  hamming_distance(const Fingerprint& other) const;
    int  bit_matches(const Fingerprint& other) const;  ///< L - hamming_distance
};
```

---

### 3.3 `SPRecord` (Service Provider Record)

```cpp
/// Stored by the owner for each SP that received a copy
struct SPRecord {
    uint64_t    sp_id_external;         ///< Publicly known SP identifier
    std::string id_internal;            ///< Internal ID used for fingerprint generation
    Fingerprint fingerprint;            ///< f = HMAC_Y(id_internal)
    int         trial_count;            ///< Number of trials in SVT (Algorithm 3)
    double      achieved_density;       ///< ‖M(R)-R‖_{1,1} of shared copy
};
```

---

### 3.4 `FingerprintParams`

```cpp
/// All tunable parameters for the fingerprinting mechanism
struct FingerprintParams {
    double  epsilon;          ///< Privacy budget ε (entry-level DP)
    double  epsilon2;         ///< SVT: ε₂ for density noise μ
    double  epsilon3;         ///< SVT: ε₃ for threshold noise ρ
    double  epsilon0;         ///< Cumulative budget (Algorithm 4)
    double  delta0;           ///< Cumulative δ (Algorithm 4)
    int32_t sensitivity;      ///< Δ
    int     K;                ///< Number of LSBs = ceil(log2(Δ)) + 1
    double  p;                ///< Flip probability = 1/(exp(ε/K)+1)
    int     L;                ///< Fingerprint length in bits (128)
    int     C;                ///< Max number of SPs
    double  Gamma;            ///< Fingerprint density threshold Γ
    int     D;                ///< Bit-match threshold for accusation

    /// Compute derived parameters from ε and Δ
    static FingerprintParams from_epsilon(double epsilon, int32_t sensitivity, int C);
};
```

---

### 3.5 `ExtractionResult`

```cpp
struct ExtractionResult {
    Fingerprint extracted_fp;       ///< f̂: majority-voted extracted fingerprint
    std::vector<int> c0;            ///< c₀[l]: count decoded as 0, l=0..L-1
    std::vector<int> c1;            ///< c₁[l]: count decoded as 1, l=0..L-1
    int num_positions_processed;    ///< Total fingerprinted positions found in R̄
    int num_records_matched;        ///< Records found in both R̄ and R
};
```

---

## 4. Module: FingerprintGenerator

**Responsibility:** Given the owner's secret key Y and an SP's internal ID, produce the 128-bit fingerprint bit-string `f = HMAC_Y(ID_internal)`.

### Class Diagram

```
┌──────────────────────────────────────────────────────┐
│                  FingerprintGenerator                  │
├──────────────────────────────────────────────────────┤
│ - secret_key_: std::vector<uint8_t>                  │
│ - hmac_: HmacSha256                                  │
├──────────────────────────────────────────────────────┤
│ + FingerprintGenerator(secret_key: bytes)            │
│ + generate(id_internal: string) → Fingerprint        │
│ + generate_internal_id(sp_key: bytes,                │
│                        trial: int) → string          │
│ + derive_sp_key(id_external: uint64_t) → bytes       │
└──────────────────────────────────────────────────────┘
              │ uses
              ▼
┌──────────────────────────────────────────────────────┐
│                     HmacSha256                        │
├──────────────────────────────────────────────────────┤
│ + compute(key: bytes, msg: bytes) → bytes[32]        │
│ + compute_md5(key: bytes, msg: bytes) → bytes[16]    │
└──────────────────────────────────────────────────────┘
```

### Interface

```cpp
class FingerprintGenerator {
public:
    explicit FingerprintGenerator(const std::vector<uint8_t>& secret_key);

    /// f = HMAC_Y(id_internal), truncated/used as 128 bits
    Fingerprint generate(const std::string& id_internal) const;

    /// ID_internal = Hash(K_c || trial_number)
    /// K_c = derive_sp_key(id_external)
    std::string generate_internal_id(const std::vector<uint8_t>& sp_key,
                                     int trial) const;

    /// Derive SP-specific sub-key K_c from master key Y and external ID
    /// K_c = HMAC_Y("SP_KEY_" || id_external)
    std::vector<uint8_t> derive_sp_key(uint64_t id_external) const;

private:
    std::vector<uint8_t> secret_key_;
    HmacSha256           hmac_;
};
```

### Input / Output

| | Type | Description |
|--|------|-------------|
| **Input** | `secret_key` | 32-byte owner key Y |
| **Input** | `id_internal` | String identifier for one SP |
| **Output** | `Fingerprint` | 128-bit bit-string f |

### Time Complexity

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| `generate()` | O(1) | Single HMAC-MD5 call (constant input size) |
| `generate_internal_id()` | O(1) | Single HMAC call |
| `derive_sp_key()` | O(1) | Single HMAC call |

---

## 5. Module: FingerprintInserter

**Responsibility:** Implement **Algorithm 1** — embed fingerprint `f` into database R using bit-level random response to produce M(R).

### Class Diagram

```
┌────────────────────────────────────────────────────────────┐
│                   FingerprintInserter                       │
├────────────────────────────────────────────────────────────┤
│ - params_: FingerprintParams                               │
│ - secret_key_: std::vector<uint8_t>                        │
│ - prng_: PrngCtr                                           │
├────────────────────────────────────────────────────────────┤
│ + FingerprintInserter(params, secret_key)                  │
│ + insert(db: RelationalDatabase,                           │
│          fp: Fingerprint,                                  │
│          id_internal: string)                              │
│          → RelationalDatabase                              │
│ - compute_seed(pk: uint64, t: int, k: int) → bytes        │
│ - is_selected(seed: bytes) → bool                         │
│ - get_mask_bit(seed: bytes) → int                         │
│ - get_fp_index(seed: bytes) → int                         │
│ - mark_bit(original: int, x: int, f_l: int) → int        │
└────────────────────────────────────────────────────────────┘
              │ uses
              ▼
┌────────────────────────────────────────────────────────────┐
│                      PrngCtr                               │
├────────────────────────────────────────────────────────────┤
│ + PrngCtr(seed: bytes)                                     │
│ + next_uint32() → uint32_t                                 │
│ + get_u1u2u3(seed: bytes)                                  │
│       → tuple<uint32_t, uint32_t, uint32_t>               │
└────────────────────────────────────────────────────────────┘
```

### Interface

```cpp
class FingerprintInserter {
public:
    FingerprintInserter(const FingerprintParams& params,
                        const std::vector<uint8_t>& secret_key);

    /// Algorithm 1: produces M(R)
    /// Caller must also pass the pre-generated fingerprint fp
    RelationalDatabase insert(const RelationalDatabase& db,
                              const Fingerprint& fp,
                              const std::string& id_internal) const;

    /// Compute L1,1 density of the result without storing it (used in SVT check)
    double compute_density(const RelationalDatabase& original,
                           const Fingerprint& fp,
                           const std::string& id_internal) const;

private:
    FingerprintParams          params_;
    std::vector<uint8_t>       secret_key_;
    PrngCtr                    prng_;

    /// s = HMAC(secret_key, PK_bytes || t_bytes || k_bytes)
    /// Returns 16 bytes used as AES-CTR seed
    std::vector<uint8_t> compute_seed(uint64_t primary_key,
                                      int t, int k) const;

    /// U1(s) mod floor(1/(2p)) == 0
    bool is_selected(const std::vector<uint8_t>& seed) const;

    /// x = U2(s) % 2
    int get_mask_bit(const std::vector<uint8_t>& seed) const;

    /// l = U3(s) % L
    int get_fp_index(const std::vector<uint8_t>& seed) const;
};
```

### Algorithm 1 — Internal Flow

```
For each record i (row):
  For each attribute t:
    if !domains[t].fingerprint: skip
    K_t = domains[t].num_bits
    effective_K = min(params_.K, K_t)
    For k = 1 to effective_K:   ← LSB is k=1
      seed = compute_seed(record.primary_key, t, k)
      [U1, U2, U3] = prng.get_u1u2u3(seed)
      selection_threshold = floor(1 / (2 * params_.p))
      if U1 % selection_threshold == 0:
        x   = U2 % 2
        l   = U3 % params_.L
        B   = x XOR fp.get_bit(l)
        new_bit = original_bit XOR B
        db_copy.set_bit(i, t, k, new_bit)
```

### Input / Output

| | Type | Description |
|--|------|-------------|
| **Input** | `RelationalDatabase` | Original database R (N × T) |
| **Input** | `Fingerprint` | 128-bit fingerprint f |
| **Input** | `id_internal` | SP's internal ID string |
| **Output** | `RelationalDatabase` | Fingerprinted copy M(R) |

### Time Complexity

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| `insert()` | O(N × T × K) | Per bit: 1 HMAC seed + 3 PRNG outputs. K ≤ 4 for Census |
| `compute_density()` | O(N × T × K) | Same loop, accumulate L1 diff only |
| `compute_seed()` | O(1) | HMAC-SHA256 of ~20 bytes |

**Dominant cost:** HMAC computation per (i, t, k) triple.  
For N=32561, T=13, K=4: ~1.7M HMAC calls per insertion.  
Each HMAC call ≈ 100ns → ~170ms per insertion (single-threaded).

**Parallelization opportunity:** Each record is independent. `insert()` can be parallelized over rows with OpenMP.

---

## 6. Module: FingerprintExtractor

**Responsibility:** Implement **Algorithm 2** — given a leaked database R̄ and the original R, recover the embedded fingerprint via majority voting on per-bit counters.

### Class Diagram

```
┌────────────────────────────────────────────────────────────┐
│                  FingerprintExtractor                       │
├────────────────────────────────────────────────────────────┤
│ - params_: FingerprintParams                               │
│ - secret_key_: std::vector<uint8_t>                        │
├────────────────────────────────────────────────────────────┤
│ + FingerprintExtractor(params, secret_key)                 │
│ + extract(leaked: RelationalDatabase,                      │
│           original: RelationalDatabase)                    │
│           → ExtractionResult                               │
│ - recover_mark_bit(leaked_bit: int,                        │
│                    original_bit: int) → int               │
│ - recover_fp_bit(x: int, B: int) → int                    │
│ - majority_vote(c0: vector<int>,                           │
│                 c1: vector<int>) → Fingerprint             │
└────────────────────────────────────────────────────────────┘
```

### Interface

```cpp
class FingerprintExtractor {
public:
    FingerprintExtractor(const FingerprintParams& params,
                         const std::vector<uint8_t>& secret_key);

    /// Algorithm 2: extract fingerprint from leaked database
    /// leaked and original are matched by primary key
    ExtractionResult extract(const RelationalDatabase& leaked,
                             const RelationalDatabase& original) const;

private:
    FingerprintParams    params_;
    std::vector<uint8_t> secret_key_;

    /// B_recovery = leaked_bit XOR original_bit
    int recover_mark_bit(int leaked_bit, int original_bit) const;

    /// f_l = x XOR B_recovery
    int recover_fp_bit(int x, int B) const;

    /// For each l: f_hat[l] = 1 iff c1[l] > c0[l]
    Fingerprint majority_vote(const std::vector<int>& c0,
                              const std::vector<int>& c1) const;

    /// Build a lookup map: primary_key → record_index for original DB
    std::unordered_map<uint64_t, size_t>
    build_pk_index(const RelationalDatabase& db) const;
};
```

### Algorithm 2 — Internal Flow

```
c0 = [0] * L,  c1 = [0] * L

Build primary-key index: pk_map[pk] = row_index in original

For each record i in leaked DB:
  pk = leaked.records[i].primary_key
  if pk not in pk_map: skip  ← subset attack may remove rows
  orig_idx = pk_map[pk]

  For each attribute t (fingerprintable):
    effective_K = min(params_.K, domains[t].num_bits)
    For k = 1 to effective_K:
      seed = compute_seed(pk, t, k)
      [U1, U2, U3] = prng.get_u1u2u3(seed)
      if U1 % floor(1/(2p)) == 0:       ← same selection logic as Algorithm 1
        x = U2 % 2
        l = U3 % L
        leaked_bit   = leaked.get_bit(i, t, k)
        original_bit = original.get_bit(orig_idx, t, k)
        B_rec = leaked_bit XOR original_bit
        f_l   = x XOR B_rec
        if f_l == 0: c0[l]++
        else:        c1[l]++

f_hat = majority_vote(c0, c1)
return ExtractionResult{f_hat, c0, c1, total_positions, matched_records}
```

### Input / Output

| | Type | Description |
|--|------|-------------|
| **Input** | `leaked` | R̄: potentially distorted/subset database |
| **Input** | `original` | R: original database for comparison |
| **Output** | `ExtractionResult` | Extracted fingerprint + counters |

### Time Complexity

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| `extract()` | O(N̄ × T × K) | N̄ = records in leaked DB (≤ N) |
| `build_pk_index()` | O(N̄) | Hash map construction |
| `majority_vote()` | O(L) | L = 128, negligible |

---

## 7. Module: FingerprintDetector

**Responsibility:** Compare the extracted fingerprint f̂ against all stored SP fingerprints to identify the traitor. Compute bit-match scores and apply the detection threshold D.

### Class Diagram

```
┌────────────────────────────────────────────────────────────┐
│                  FingerprintDetector                        │
├────────────────────────────────────────────────────────────┤
│ - sp_records_: vector<SPRecord>                            │
│ - detection_threshold_D_: int                              │
├────────────────────────────────────────────────────────────┤
│ + FingerprintDetector(D: int)                              │
│ + register_sp(record: SPRecord) → void                     │
│ + detect(result: ExtractionResult) → DetectionResult       │
│ + compute_threshold(C: int, L: int) → int                 │
│ + bit_matches(fp1: Fingerprint,                            │
│               fp2: Fingerprint) → int                     │
└────────────────────────────────────────────────────────────┘
```

### Interface

```cpp
struct DetectionResult {
    int     accused_sp_index;    ///< Index into sp_records_ (-1 if none)
    uint64_t accused_sp_external_id;
    int     max_matches;         ///< Highest bit-match count found
    int     threshold_D;         ///< D threshold used
    bool    accused;             ///< true if max_matches > D
    std::vector<std::pair<int,int>> all_scores;  ///< (sp_idx, bit_matches) for all SPs
};

class FingerprintDetector {
public:
    explicit FingerprintDetector(int detection_threshold_D);

    /// Register an SP's record (called after each successful sharing)
    void register_sp(const SPRecord& record);

    /// Compare extracted fingerprint against all registered SPs
    DetectionResult detect(const ExtractionResult& result) const;

    /// Compute D given C (number of SPs) and L (fingerprint length)
    /// D is the minimum such that C(L, D) * (1/2)^L < 1/C
    static int compute_threshold(int C, int L);

    /// Count bit matches between two fingerprints
    static int bit_matches(const Fingerprint& a, const Fingerprint& b);

private:
    std::vector<SPRecord> sp_records_;
    int detection_threshold_D_;
};
```

### Detection Logic

```
For each registered SP j:
    matches[j] = bit_matches(f_hat, sp_records_[j].fingerprint)

accused = argmax_j(matches[j])
if matches[accused] > D:
    return DetectionResult{accused, ...}
```

### Threshold D Computation

Per Appendix C of the paper: find minimum D such that:
```
sum_{d=D}^{L} C(L,d) * (1/2)^L >= 1/C
```
i.e., probability that a random L-bit string has ≥ D matches with the true fingerprint exceeds 1/C. In practice for L=128, C=100: D ≈ 80–90.

### Input / Output

| | Type | Description |
|--|------|-------------|
| **Input** | `ExtractionResult` | Extracted f̂ from leaked database |
| **Input** | `sp_records_` | Stored fingerprints of all SPs |
| **Output** | `DetectionResult` | Accused SP + scores |

### Time Complexity

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| `detect()` | O(C × L) | C SPs, L=128 bits each via popcount |
| `compute_threshold()` | O(L²) | Binomial sum, precomputable |
| `register_sp()` | O(1) | Append to vector |

---

## 8. Module: PrivacyBudgetManager

**Responsibility:** Implement **Algorithms 3 & 4** — SVT-based mechanism for sharing fingerprinted databases with multiple SPs while controlling cumulative privacy loss. Manages the generation of ID_internal candidates and noisy density comparison.

### Class Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                  PrivacyBudgetManager                         │
├──────────────────────────────────────────────────────────────┤
│ - params_: FingerprintParams                                 │
│ - secret_key_: std::vector<uint8_t>                          │
│ - inserter_: FingerprintInserter                             │
│ - generator_: FingerprintGenerator                           │
│ - laplace_: LaplaceNoise                                     │
│ - sp_counter_: int                                           │
├──────────────────────────────────────────────────────────────┤
│ + PrivacyBudgetManager(params, secret_key)                   │
│                                                               │
│ [Algorithm 3 — single SP]                                    │
│ + determine_internal_id(db: RelationalDatabase,               │
│                          id_external: uint64_t)              │
│                          → optional<SPRecord>                │
│                                                               │
│ [Algorithm 4 — multiple SPs]                                 │
│ + share_with_multiple(db: RelationalDatabase,                 │
│                        sp_externals: vector<uint64_t>)       │
│                        → vector<pair<SPRecord, RelationalDB>>│
│                                                               │
│ + compute_cumulative_budget(C: int, delta_prime: double,     │
│                              eps: double, eps23: double)     │
│                              → double                        │
│ + allocate_epsilon23(epsilon_star: double)                   │
│                      → pair<double,double>                   │
└──────────────────────────────────────────────────────────────┘
              │ uses
              ▼
┌──────────────────────────────────────────────────────────────┐
│                     LaplaceNoise                              │
├──────────────────────────────────────────────────────────────┤
│ - rng_: mt19937_64                                           │
├──────────────────────────────────────────────────────────────┤
│ + LaplaceNoise(seed: uint64_t)                               │
│ + sample(sensitivity: double,                                │
│           epsilon: double) → double                          │
│   // Returns Lap(sensitivity/epsilon)                        │
└──────────────────────────────────────────────────────────────┘
```

### Interface

```cpp
class PrivacyBudgetManager {
public:
    PrivacyBudgetManager(const FingerprintParams& params,
                          const std::vector<uint8_t>& secret_key);

    /// Algorithm 3: Find ID_internal for ONE SP using SVT noisy comparison
    /// Returns std::nullopt if max_trials exceeded (should not happen in practice)
    std::optional<SPRecord>
    determine_internal_id(const RelationalDatabase& db,
                          uint64_t id_external,
                          int max_trials = 100);

    /// Algorithm 4: Share with C SPs, compose Algorithm 3 C times
    /// Returns vector of (SPRecord, fingerprinted DB) pairs
    std::vector<std::pair<SPRecord, RelationalDatabase>>
    share_with_multiple(const RelationalDatabase& db,
                        const std::vector<uint64_t>& sp_externals);

    /// Theorem 4: compute ε₀ for C sharings
    static double compute_cumulative_budget(int C, double delta_prime,
                                             double eps, double eps23);

    /// Optimal split: ε₂ = ε₃ = ε*/2
    static std::pair<double,double> allocate_epsilon23(double epsilon_star);

private:
    FingerprintParams          params_;
    std::vector<uint8_t>       secret_key_;
    FingerprintInserter        inserter_;
    FingerprintGenerator       generator_;
    LaplaceNoise               laplace_;
    int                        sp_counter_{0};

    /// Algorithm 3 core: noisy density comparison
    /// Returns true (⊤) if density + μ > Γ + ρ
    bool noisy_comparison(double density) const;
};
```

### Algorithm 3 — Internal Flow

```cpp
std::optional<SPRecord>
PrivacyBudgetManager::determine_internal_id(
    const RelationalDatabase& db,
    uint64_t id_external,
    int max_trials)
{
    auto sp_key = generator_.derive_sp_key(id_external);

    for (int i = 1; i <= max_trials; ++i) {
        // Line 2: generate candidate ID_internal
        std::string id_internal = generator_.generate_internal_id(sp_key, i);

        // Line 3: generate fingerprint (NOT shared yet)
        Fingerprint fp = generator_.generate(id_internal);

        // Line 4: compute fingerprint density
        double density = inserter_.compute_density(db, fp, id_internal);

        // Lines 5-6: noisy comparison with Laplace noise
        double mu  = laplace_.sample(params_.sensitivity, params_.epsilon2);
        double rho = laplace_.sample(params_.sensitivity, params_.epsilon3);

        if (density + mu > params_.Gamma + rho) {
            // ⊤: Accept this ID_internal
            SPRecord record;
            record.sp_id_external = id_external;
            record.id_internal    = id_internal;
            record.fingerprint    = fp;
            record.trial_count    = i;
            record.achieved_density = density;
            return record;
        }
        // ⊥: try next trial
    }
    return std::nullopt;
}
```

### Input / Output

| | Type | Description |
|--|------|-------------|
| **Input** | `db` | Original database R |
| **Input** | `sp_externals` | List of C SP external IDs |
| **Output** | `vector<pair<SPRecord, RelationalDB>>` | Accepted records + fingerprinted copies |

### Time Complexity

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| `determine_internal_id()` | O(trials × N × T × K) | Expected trials ≈ 1.5 (experimentally) |
| `share_with_multiple()` | O(C × trials × N × T × K) | C SPs, dominant cost |

---

## 9. Module: AttackSimulator

**Responsibility:** Simulate three attacks from the paper: random bit flipping, subset attack, and correlation attack.

### Class Diagram

```
┌──────────────────────────────────────────────────┐
│              AttackSimulator  (abstract)          │
├──────────────────────────────────────────────────┤
│ # rng_: mt19937_64                               │
├──────────────────────────────────────────────────┤
│ + AttackSimulator(seed: uint64_t)                │
│ + attack(db: RelationalDatabase,                 │
│           params: AttackParams)                  │
│           → RelationalDatabase  [pure virtual]   │
└──────────────────────────────────────────────────┘
                      △
          ┌───────────┴──────────┐
          │                      │
┌─────────────────────┐  ┌──────────────────────┐
│ RandomFlippingAttack│  │   SubsetAttack        │
├─────────────────────┤  ├──────────────────────┤
│ - gamma_rnd_: double│  │ - gamma_sub_: double  │
├─────────────────────┤  ├──────────────────────┤
│ + attack(...)       │  │ + attack(...)         │
│   // flip K LSBs    │  │   // include row with │
│   // with prob γ    │  │   // prob γ_sub       │
└─────────────────────┘  └──────────────────────┘

┌──────────────────────────────────────────┐
│           CorrelationAttack              │
├──────────────────────────────────────────┤
│ - tau_: double   // correlation threshold│
├──────────────────────────────────────────┤
│ + attack(db: RelationalDatabase,         │
│           original: RelationalDatabase,  │
│           params: AttackParams)          │
│           → RelationalDatabase           │
│ + estimate_joint_dist(db: ...)           │
│       → JointDistribution               │
└──────────────────────────────────────────┘
```

### Interface

```cpp
struct AttackParams {
    double gamma_rnd;   ///< Bit-flip probability for random flipping attack
    double gamma_sub;   ///< Row inclusion probability for subset attack
    double tau;         ///< Correlation threshold τ for correlation attack
    int    K;           ///< Number of LSBs (same as fingerprinting)
};

class AttackSimulator {
public:
    explicit AttackSimulator(uint64_t seed = 42);
    virtual ~AttackSimulator() = default;
    virtual RelationalDatabase attack(const RelationalDatabase& db,
                                       const AttackParams& params) = 0;
protected:
    std::mt19937_64 rng_;
};

/// Random bit flipping: flip each of K LSBs of each entry with prob gamma_rnd
class RandomFlippingAttack : public AttackSimulator {
public:
    explicit RandomFlippingAttack(double gamma_rnd, uint64_t seed = 42);
    RelationalDatabase attack(const RelationalDatabase& db,
                               const AttackParams& params) override;
private:
    double gamma_rnd_;
};

/// Subset attack: include each record with probability gamma_sub
class SubsetAttack : public AttackSimulator {
public:
    explicit SubsetAttack(double gamma_sub, uint64_t seed = 42);
    RelationalDatabase attack(const RelationalDatabase& db,
                               const AttackParams& params) override;
private:
    double gamma_sub_;
};

/// Correlation attack: exploit joint distribution discrepancies to detect
/// and flip potentially fingerprinted bits
class CorrelationAttack : public AttackSimulator {
public:
    explicit CorrelationAttack(double tau, uint64_t seed = 42);

    /// Requires access to original database to estimate joint distributions
    RelationalDatabase attack(const RelationalDatabase& fingerprinted,
                               const RelationalDatabase& original,
                               const AttackParams& params);

    RelationalDatabase attack(const RelationalDatabase& db,
                               const AttackParams& params) override;

private:
    double tau_;
    using JointDist = std::map<std::pair<int32_t,int32_t>, double>;

    JointDist estimate_joint_distribution(
        const RelationalDatabase& db, int t, int z) const;
};
```

### Input / Output

| Module | Input | Output |
|--------|-------|--------|
| `RandomFlippingAttack` | Fingerprinted DB + γ_rnd | Distorted DB |
| `SubsetAttack` | Fingerprinted DB + γ_sub | Subset DB |
| `CorrelationAttack` | Fingerprinted DB + original DB + τ | Distorted DB |

### Time Complexity

| Attack | Complexity | Notes |
|--------|-----------|-------|
| `RandomFlippingAttack::attack()` | O(N × T × K) | Per-bit Bernoulli trial |
| `SubsetAttack::attack()` | O(N) | Per-row Bernoulli trial |
| `CorrelationAttack::attack()` | O(N × T² × V²) | V = domain size per attribute; joint dist estimation dominates |

---

## 10. Module: DatasetLoader

**Responsibility:** Load and preprocess the UCI Nursery and Census datasets, performing integer encoding of categorical and discrete attributes.

### Interface

```cpp
class DatasetLoader {
public:
    virtual ~DatasetLoader() = default;
    virtual RelationalDatabase load(const std::string& filepath) = 0;
};

class CsvLoader : public DatasetLoader {
public:
    /// separator: ',' or ' '
    /// pk_column: column index used as primary key (-1 = auto-generate row index)
    /// skip_header: whether first line is a header
    explicit CsvLoader(char separator = ',',
                        int pk_column = -1,
                        bool skip_header = false);

    RelationalDatabase load(const std::string& filepath) override;
};

class NurseryLoader : public CsvLoader {
public:
    NurseryLoader();
    RelationalDatabase load(const std::string& filepath) override;
    // Encodes 8 categorical attributes → integers
    // Excludes label column from fingerprinting
    // Δ = 4 (or 1 with restricted sensitivity)
};

class CensusLoader : public CsvLoader {
public:
    CensusLoader();
    RelationalDatabase load(const std::string& filepath) override;
    // Encodes 13 discrete/categorical attributes → integers
    // Drops fnlwgt; binary-encodes capital-gain, capital-loss, native-country
    // Δ = 15; K = 4
};
```

### Encoding Logic

```
For categorical attributes (e.g., "marital-status"):
  1. Collect all unique values
  2. Sort lexicographically (or by word embedding similarity)
  3. Assign ascending integers 0, 1, 2, ...

For discrete attributes (e.g., "age"):
  1. Sort unique values in ascending order
  2. Divide into non-overlapping ranges
  3. Encode ranges as ascending integers

For binary attributes:
  Map to {0, 1}
```

---

## 11. Module: ExperimentRunner

**Responsibility:** Orchestrate end-to-end experiments corresponding to Sections VII-B (single sharing) and VII-C (multiple sharing) of the paper.

### Interface

```cpp
struct ExperimentConfig {
    std::string dataset_path;
    std::string dataset_name;        // "nursery" or "census"
    std::vector<double> epsilons;    // ε values to sweep
    int C;                           // number of SPs for multiple sharing
    double gamma_rnd;                // attack parameter
    double gamma_sub;                // attack parameter
    int num_trials;                  // repetitions for averaging
    std::string output_csv;          // results output file
};

struct ExperimentResult {
    double epsilon;
    double p;
    int    K;
    double fingerprint_density;
    int    bit_matches_after_attack;
    double accuracy_loss_svm;        // optional
    double total_deviation_pca;      // optional
    int    num_trials_for_id;        // SVT trials needed
};

class ExperimentRunner {
public:
    explicit ExperimentRunner(const ExperimentConfig& config);

    /// Section VII-B: single sharing, vary ε
    std::vector<ExperimentResult> run_single_sharing();

    /// Section VII-C: multiple sharing (C SPs), measure cumulative privacy loss
    std::vector<ExperimentResult> run_multiple_sharing();

    /// Save results to CSV
    void save_results(const std::vector<ExperimentResult>& results,
                       const std::string& path) const;

private:
    ExperimentConfig config_;
};
```

### MetricsCollector (helper)

```cpp
class MetricsCollector {
public:
    /// Bit matches between f_hat and ground truth f
    static int count_bit_matches(const Fingerprint& extracted,
                                  const Fingerprint& truth);

    /// Fingerprint density: ‖M(R) - R‖_{1,1}
    static double fingerprint_density(const RelationalDatabase& fingerprinted,
                                       const RelationalDatabase& original);

    /// L2 distance between databases (for utility measurement)
    static double l2_distance(const RelationalDatabase& a,
                               const RelationalDatabase& b);
};
```

---

## 12. Inter-Module Data Flow

### Single Sharing (Algorithm 1 + 2)

```
NurseryLoader/CensusLoader
      │ RelationalDatabase R
      ▼
FingerprintParams::from_epsilon(ε, Δ, C)
      │ FingerprintParams{K, p, L, D, ...}
      ▼
FingerprintGenerator
      │ Fingerprint f
      ▼
FingerprintInserter::insert(R, f, id_internal)
      │ RelationalDatabase M(R)
      ▼
AttackSimulator::attack(M(R), params)        ← optional
      │ RelationalDatabase R̄
      ▼
FingerprintExtractor::extract(R̄, R)
      │ ExtractionResult{f_hat, c0, c1}
      ▼
FingerprintDetector::detect(result)
      │ DetectionResult{accused_sp, bit_matches}
      ▼
MetricsCollector / ExperimentRunner
```

### Multiple Sharing (Algorithms 3 + 4)

```
RelationalDatabase R
      │
      ▼
PrivacyBudgetManager::share_with_multiple(R, sp_ids)
      │
      ├── For each SP c:
      │     ├── Algorithm 3: determine_internal_id()
      │     │     ├── generate candidate ID_internal_c
      │     │     ├── FingerprintInserter::compute_density()
      │     │     ├── LaplaceNoise::sample() × 2 (μ, ρ)
      │     │     └── if density + μ > Γ + ρ: accept
      │     └── Algorithm 1: FingerprintInserter::insert()
      │
      ▼
vector<pair<SPRecord, RelationalDB>>
      │
      ▼
For each shared copy: attack → extract → detect
```

---

## 13. Error Handling Strategy

```cpp
// Use a Result type for operations that can fail
template<typename T>
using Result = std::variant<T, std::string>;  // T on success, error msg on failure

// Precondition checks use assertions in debug, exceptions in release
class FingerprintError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class InvalidParamsError : public FingerprintError { ... };
class CryptoError        : public FingerprintError { ... };
class DatabaseError      : public FingerprintError { ... };
```

Key invariants checked at runtime:
- `p < 0.5` (required for privacy proof to hold)
- `K ≥ 1` (sensitivity must be ≥ 1)
- `epsilon > 0`
- Primary keys are unique in RelationalDatabase
- `id_internal` is never reused across SPs

---

## 14. Build & Dependency Graph

```
CMakeLists.txt (root)
│
├── crypto/          ← depends on: OpenSSL
│   HmacSha256
│   PrngCtr
│
├── database/        ← depends on: (none external)
│   RelationalDatabase
│   DatabaseEncoder
│
├── fingerprint/     ← depends on: crypto/, database/
│   FingerprintGenerator
│   FingerprintInserter
│   FingerprintExtractor
│   FingerprintDetector
│
├── privacy/         ← depends on: fingerprint/, crypto/
│   PrivacyBudgetManager
│   LaplaceNoise
│
├── datasets/        ← depends on: database/
│   DatasetLoader
│   NurseryLoader
│   CensusLoader
│
├── attacks/         ← depends on: database/
│   AttackSimulator
│   RandomFlippingAttack
│   SubsetAttack
│   CorrelationAttack
│
└── experiments/     ← depends on: ALL modules
    ExperimentRunner
    MetricsCollector
```

### External Dependencies

| Library | Purpose | Version | Install |
|---------|---------|---------|---------|
| **OpenSSL** | HMAC-SHA256, HMAC-MD5, AES-CTR | ≥ 1.1.1 | `brew install openssl` / `apt install libssl-dev` |
| **Google Test** | Unit testing | ≥ 1.12 | via CMake FetchContent |
| **nlohmann/json** | Config file parsing | ≥ 3.10 | via CMake FetchContent |

---

## 15. Time & Space Complexity Summary

| Module | Key Operation | Time | Space |
|--------|--------------|------|-------|
| `FingerprintGenerator` | `generate()` | O(1) | O(L) |
| `FingerprintInserter` | `insert()` | **O(N·T·K)** | O(N·T) |
| `FingerprintInserter` | `compute_density()` | O(N·T·K) | O(1) extra |
| `FingerprintExtractor` | `extract()` | **O(N̄·T·K)** | O(N) for pk map |
| `FingerprintDetector` | `detect()` | O(C·L) | O(C·L) for records |
| `PrivacyBudgetManager` | `determine_internal_id()` | O(trials·N·T·K) | O(N·T) |
| `PrivacyBudgetManager` | `share_with_multiple()` | **O(C·N·T·K)** | O(C·N·T) |
| `RandomFlippingAttack` | `attack()` | O(N·T·K) | O(N·T) |
| `SubsetAttack` | `attack()` | O(N) | O(N·T) |
| `CorrelationAttack` | `attack()` | O(N·T²·V²) | O(T²·V²) |
| `NurseryLoader` | `load()` | O(N·T) | O(N·T) |
| `CensusLoader` | `load()` | O(N·T) | O(N·T) |

**Dominant bottleneck:** HMAC computation per (i, t, k) triple in `FingerprintInserter`.

For Census (N=32561, T=13, K=4):
- Total bit positions: 32561 × 13 × 4 ≈ 1.69M positions
- Expected selected positions (at 2p ≈ 0.4): ≈ 676K
- At 100ns/HMAC: ≈ 170ms per insertion, ≈ 68ms per extraction

**Parallelization strategy:**
- `insert()` and `extract()` can parallelize over rows using `#pragma omp parallel for`
- `share_with_multiple()` can parallelize over SPs (independent PRNG streams per SP)

---

## 16. Key Design Decisions

### D1: Seed Construction
Use HMAC-SHA256(key=Y, msg=PK||t_bytes||k_bytes) as the 16-byte AES seed.
- Ensures collision-resistance across (PK, t, k) triples
- The secret key Y makes seeds unpredictable to SPs

### D2: U₁/U₂/U₃ from AES-CTR Stream
Generate a 12-byte stream from AES-CTR(key=seed[:16], nonce=0); extract 3 × uint32_t.
- Cryptographically secure
- Fast (1 AES block per 3 PRNG values)

### D3: HMAC-MD5 for Fingerprint Generation
`f = HMAC_MD5(key=Y, msg=id_internal)` → 16 bytes = 128 bits.
- Matches paper specification exactly
- Note: MD5 is weak as a standalone hash but HMAC-MD5 remains secure for MAC purposes

### D4: Row-Indexed Primary Keys for Datasets
UCI datasets lack natural primary keys. Assign sequential 0-indexed uint64_t primary keys.
- Stable across insertion/extraction (same row order maintained)
- Owner stores the original ordering

### D5: Attribute Indexing
t is 0-indexed; k=1 is the LSB (1-indexed from LSB).  
`get_bit(i, t, k)` returns `(attributes[t] >> (k-1)) & 1`.

### D6: Separation of Density Computation vs. Insertion
`compute_density()` shares the same inner loop as `insert()` but does not modify the database, enabling the SVT noisy comparison without materializing the full fingerprinted copy unnecessarily.

### D7: Thread Safety
`FingerprintInserter` and `FingerprintExtractor` are stateless after construction (all state is in `params_` and `secret_key_`). Safe to use from multiple threads concurrently for different (i, fp, id_internal) tuples.

---

## 17. Unit Test Plan

| Test File | Scenarios Covered |
|-----------|-------------------|
| `test_fingerprint_generator.cpp` | Different (Y, id_internal) → different f; same inputs → same f |
| `test_fingerprint_inserter.cpp` | K/p derivation from ε; bit selection rate ≈ 2p; M(R) ≠ R; density bounds |
| `test_fingerprint_extractor.cpp` | extract(insert(R, f)) ≈ f (no attack); f recoverable after 50% flip |
| `test_fingerprint_detector.cpp` | Correct SP accused; D threshold formula |
| `test_privacy_budget.cpp` | Algorithm 3 terminates in ≤ 5 trials; Theorem 4 formula |
| `test_attacks.cpp` | Random flip fraction ≈ γ_rnd; subset fraction ≈ γ_sub |
| `test_prng.cpp` | U₁/U₂/U₃ uniformity (chi-squared test); seed uniqueness |
| `test_integration.cpp` | Full pipeline: load → insert → attack → extract → detect |
