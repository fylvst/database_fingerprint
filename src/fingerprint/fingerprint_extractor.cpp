/**
 * fingerprint_extractor.cpp
 *
 * Implementation of Algorithm 2: Fingerprint Extraction with Majority Voting.
 */

#include "fingerprint_extractor.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>

// ============================================================================
// Constructor
// ============================================================================

FingerprintExtractor::FingerprintExtractor(const FingerprintParams& params,
                                             const std::vector<uint8_t>& owner_secret)
    : params_(params), owner_secret_(owner_secret) {

    if (owner_secret.empty()) {
        throw std::invalid_argument("FingerprintExtractor: owner_secret must not be empty");
    }
    if (params.p <= 0.0 || params.p >= 0.5) {
        throw std::invalid_argument("FingerprintExtractor: p must be in (0, 0.5)");
    }
}

// ============================================================================
// Inner helpers (identical logic to FingerprintInserter — must be consistent)
// ============================================================================

std::unordered_map<uint64_t, size_t>
FingerprintExtractor::build_pk_index(const RelationalDatabase& db) const {
    std::unordered_map<uint64_t, size_t> idx;
    idx.reserve(db.num_records());
    for (size_t i = 0; i < db.num_records(); ++i) {
        idx[db.records[i].primary_key] = i;
    }
    return idx;
}

crypto::Bytes16 FingerprintExtractor::compute_seed(uint64_t primary_key,
                                                    uint16_t t,
                                                    uint16_t k) const {
    return crypto::make_seed(owner_secret_, primary_key, t, k);
}

bool FingerprintExtractor::is_selected(uint32_t u1) const {
    uint32_t period = static_cast<uint32_t>(std::floor(1.0 / (2.0 * params_.p)));
    if (period == 0) period = 1;
    return (u1 % period) == 0;
}

int FingerprintExtractor::compute_mask_bit(uint32_t u2) const {
    return static_cast<int>(u2 & 1u);
}

int FingerprintExtractor::compute_fp_index(uint32_t u3) const {
    return static_cast<int>(u3 % static_cast<uint32_t>(params_.L));
}

int FingerprintExtractor::recover_mark_bit(int leaked_bit, int original_bit) const {
    // Paper: "B = r̄^i_{t,k} XOR r^i_{t,k}"
    //
    // If no attack: leaked_bit = original_bit XOR B → B̂ = original_bit XOR leaked_bit = B ✓
    // If attacked (bit flipped): B̂ = 1 - B (wrong), contributing a wrong vote
    return leaked_bit ^ original_bit;
}

int FingerprintExtractor::recover_fp_bit(int x, int B) const {
    // Paper: "fingerprint bit at index l as f_l = x XOR B"
    return x ^ B;
}

Fingerprint FingerprintExtractor::majority_vote(const std::vector<int>& c0,
                                                  const std::vector<int>& c1) const {
    // Paper: "sets f_l = 1, if c1[l] > c0[l], otherwise f_l = 0"
    //
    // ASSUMPTION: ties → 0; zero evidence → 0.
    Fingerprint fp{};
    for (int l = 0; l < params_.L; ++l) {
        int bit = (c1[l] > c0[l]) ? 1 : 0;
        fp.set_bit(l, bit);
    }
    return fp;
}

// ============================================================================
// Algorithm 2: extract
// ============================================================================

ExtractionResult FingerprintExtractor::extract(
    const RelationalDatabase& leaked,
    const RelationalDatabase& original) const {

    if (leaked.num_attributes() != original.num_attributes()) {
        throw std::invalid_argument("extract: attribute count mismatch between leaked and original");
    }

    // Initialize counters
    std::vector<int> c0(params_.L, 0);
    std::vector<int> c1(params_.L, 0);
    int num_positions = 0;
    int num_matched   = 0;

    // Paper: "the database owner first constructs the fingerprintable sets P̄ from R̄"
    // P̄ = { r̄^i_{t,k} | i ∈ [1, N̄], t ∈ [1,T], k ∈ [1, min(K, K_t)] }
    //
    // We need to match leaked records to original records via primary key.
    auto pk_index = build_pk_index(original);

    const size_t T = leaked.num_attributes();

    for (size_t i = 0; i < leaked.num_records(); ++i) {
        uint64_t pk = leaked.records[i].primary_key;

        // Find the corresponding original record
        auto it = pk_index.find(pk);
        if (it == pk_index.end()) {
            // Record not in original (unexpected — primary keys are immutable)
            // ASSUMPTION: Skip such records silently.
            continue;
        }
        size_t orig_idx = it->second;
        ++num_matched;

        for (size_t t = 0; t < T; ++t) {
            // Skip non-fingerprinted attributes
            if (!original.domains[t].fingerprint) continue;

            int K_t        = original.domains[t].num_bits();
            int effective_K = std::min(params_.K, K_t);

            for (int k = 1; k <= effective_K; ++k) {
                // Step a: Recompute same seed as Algorithm 1
                // Paper: "using the pseudorandom seed s = Y | r_i.PrimaryKey | t | k"
                auto seed = compute_seed(pk,
                                         static_cast<uint16_t>(t),
                                         static_cast<uint16_t>(k));

                auto [u1, u2, u3] = crypto::prng_u123(seed);

                // Step b: Check selection (same condition as insertion)
                if (!is_selected(u1)) continue;

                ++num_positions;

                // Step c: Recover mask bit
                int x = compute_mask_bit(u2);

                // Step d: Recover fingerprint index
                int l = compute_fp_index(u3);

                // Step e: Recover mark bit
                // Paper: "recovers the mark bit as B = r̄^i_{t,k} XOR r^i_{t,k}"
                int leaked_bit   = leaked.get_bit(i, t, k);
                int original_bit = original.get_bit(orig_idx, t, k);
                int B_hat        = recover_mark_bit(leaked_bit, original_bit);

                // Step f: Recover fingerprint bit
                // Paper: "fingerprint bit at index l as f_l = x XOR B"
                int f_l_hat = recover_fp_bit(x, B_hat);

                // Step g: Update counter
                // Paper: "maintains and updates two counting arrays c0 and c1"
                if (f_l_hat == 0) {
                    ++c0[l];
                } else {
                    ++c1[l];
                }
            }
        }
    }

    // Step 3: Majority voting
    // Paper: "sets f_l = 1, if c1[l] > c0[l], otherwise f_l = 0"
    Fingerprint extracted = majority_vote(c0, c1);

    return ExtractionResult{
        extracted,
        c0,
        c1,
        num_positions,
        num_matched
    };
}

// ============================================================================
// count_bit_matches (static)
// ============================================================================

int FingerprintExtractor::count_bit_matches(const Fingerprint& extracted,
                                              const Fingerprint& candidate) {
    return extracted.bit_matches(candidate);
}

// ============================================================================
// identify_traitor (static)
// ============================================================================

std::pair<int, int> FingerprintExtractor::identify_traitor(
    const Fingerprint&              extracted,
    const std::vector<Fingerprint>& sp_fingerprints,
    int                             threshold_D) {

    int best_sp      = -1;
    int best_matches = 0;

    for (int j = 0; j < static_cast<int>(sp_fingerprints.size()); ++j) {
        int matches = count_bit_matches(extracted, sp_fingerprints[j]);
        if (matches > best_matches) {
            best_matches = matches;
            best_sp      = j;
        }
    }

    // Paper: "one of these SPs will be considered as guilty if there is a large
    // overlap between its fingerprint and the constructed one"
    // "the database owner can correctly identify the malicious SP as long as
    // the overlapping between fingerprints is above 50%"
    //
    // We use the computed threshold D (>50% = 64 out of 128, or computed D).
    if (best_sp >= 0 && best_matches <= threshold_D) {
        best_sp = -1;  // No SP exceeds threshold → cannot accuse
    }

    return {best_sp, best_matches};
}
