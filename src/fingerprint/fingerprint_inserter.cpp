/**
 * fingerprint_inserter.cpp
 *
 * Implementation of Algorithm 1: ε-Entry-Level DP Fingerprint Insertion.
 */

#include "fingerprint_inserter.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>

// ============================================================================
// Constructor
// ============================================================================

FingerprintInserter::FingerprintInserter(const FingerprintParams& params,
                                          const std::vector<uint8_t>& owner_secret)
    : params_(params), owner_secret_(owner_secret) {

    if (owner_secret.empty()) {
        throw std::invalid_argument("FingerprintInserter: owner_secret must not be empty");
    }
    if (params.p <= 0.0 || params.p >= 0.5) {
        throw std::invalid_argument("FingerprintInserter: p must be in (0, 0.5)");
    }
    if (params.K < 1) {
        throw std::invalid_argument("FingerprintInserter: K must be >= 1");
    }
    if (params.L != Fingerprint::LENGTH_BITS) {
        throw std::invalid_argument("FingerprintInserter: L must be 128");
    }
}

// ============================================================================
// Inner helpers
// ============================================================================

crypto::Bytes16 FingerprintInserter::compute_seed(uint64_t primary_key,
                                                   uint16_t t,
                                                   uint16_t k) const {
    return crypto::make_seed(owner_secret_, primary_key, t, k);
}

bool FingerprintInserter::is_selected(uint32_t u1) const {
    // Paper: "if U1(s) mod floor(1/(2p)) == 0"
    //
    // floor(1/(2p)) is the selection period.
    // Probability of selection = 1/floor(1/(2p)) ≈ 2p.
    //
    // Note: paper uses p such that 2p < 1 (guaranteed since p < 0.5).
    // floor(1/(2p)) >= 1 always (since 2p < 1 → 1/(2p) > 1).
    uint32_t period = static_cast<uint32_t>(std::floor(1.0 / (2.0 * params_.p)));
    if (period == 0) period = 1;  // safety guard
    return (u1 % period) == 0;
}

int FingerprintInserter::compute_mask_bit(uint32_t u2) const {
    // Paper: "checking if U2(s) is even or odd"
    // x = 0 if even, x = 1 if odd
    return static_cast<int>(u2 & 1u);
}

int FingerprintInserter::compute_fp_index(uint32_t u3) const {
    // Paper: "l = U3(s) mod L"
    return static_cast<int>(u3 % static_cast<uint32_t>(params_.L));
}

int FingerprintInserter::compute_mark_bit(int x, int f_l) const {
    // Paper: "B = x XOR f_l"
    return x ^ f_l;
}

int FingerprintInserter::apply_mark(int original_bit, int B) const {
    // Paper: "changes the bit value of r^i_{t,k} with r^i_{t,k} XOR B"
    //
    // KEY: This XORs with B (which depends on both x and f_l), NOT with f_l directly.
    // This is what makes the output dependent on the original bit value,
    // enabling the DP privacy proof in Theorem 1.
    return original_bit ^ B;
}

// ============================================================================
// Algorithm 1: insert
// ============================================================================

RelationalDatabase FingerprintInserter::insert(const RelationalDatabase& db,
                                                const Fingerprint& fp,
                                                const std::string& /*id_internal*/) const {
    // Make a deep copy — we will modify it
    RelationalDatabase result = db;

    const size_t N = db.num_records();
    const size_t T = db.num_attributes();

    // Iterate over all fingerprintable positions
    // Paper: P = { r^i_{t,k} | i∈[1,N], t∈[1,T], k∈[1, min(K, K_t)] }
    for (size_t i = 0; i < N; ++i) {
        uint64_t pk = db.records[i].primary_key;

        for (size_t t = 0; t < T; ++t) {
            // Attribute selection:
            // Paper: "only the insignificant bits (the last K bits) of all entries"
            // Skip attributes that are not fingerprinted (e.g., labels)
            if (!db.domains[t].fingerprint) continue;

            int K_t = db.domains[t].num_bits();
            // Paper: "for each r^i_{t,k} in P", where k ∈ [1, min(K, K_t)]
            int effective_K = std::min(params_.K, K_t);

            for (int k = 1; k <= effective_K; ++k) {
                // Step 1: Compute deterministic seed
                // Paper: "sets the initial seed as s = Y | r_i.PrimaryKey | t | k"
                crypto::Bytes16 seed = compute_seed(pk,
                                                    static_cast<uint16_t>(t),
                                                    static_cast<uint16_t>(k));

                // Generate U1, U2, U3 from this seed
                auto [u1, u2, u3] = crypto::prng_u123(seed);

                // Step 2: Tuple/bit selection
                // Paper: "If U1(s) mod floor(1/(2p)) == 0"
                if (!is_selected(u1)) continue;

                // Step 3: Mask bit
                // Paper: "the database owner decides the value of mask bit x by
                //         checking if U2(s) is even or odd"
                int x = compute_mask_bit(u2);

                // Step 4: Fingerprint index
                // Paper: "sets the fingerprint index l = U3(s) mod L"
                int l = compute_fp_index(u3);

                // Step 5: Mark bit
                // Paper: "it obtains the mark bit as B = x XOR f_l"
                int f_l = fp.get_bit(l);
                int B   = compute_mark_bit(x, f_l);

                // Step 6: Bit embedding
                // Paper: "finally it changes the bit value of r^i_{t,k} with r^i_{t,k} XOR B"
                int original_bit = db.get_bit(i, t, k);
                int new_bit      = apply_mark(original_bit, B);
                result.set_bit(i, t, k, new_bit);
            }
        }
    }

    return result;
}

// ============================================================================
// compute_density
// ============================================================================

double FingerprintInserter::compute_density(const RelationalDatabase& db,
                                             const Fingerprint& fp) const {
    // Simulate insertion and measure L1,1 norm between M(R) and R.
    // Paper: density = ||M(R) - R||_{1,1}
    RelationalDatabase fingerprinted = insert(db, fp, "");
    return fingerprinted.fingerprint_density(db);
}

// ============================================================================
// count_selected_positions
// ============================================================================

size_t FingerprintInserter::count_selected_positions(const RelationalDatabase& db) const {
    size_t count = 0;
    const size_t N = db.num_records();
    const size_t T = db.num_attributes();

    for (size_t i = 0; i < N; ++i) {
        uint64_t pk = db.records[i].primary_key;
        for (size_t t = 0; t < T; ++t) {
            if (!db.domains[t].fingerprint) continue;
            int effective_K = std::min(params_.K, db.domains[t].num_bits());
            for (int k = 1; k <= effective_K; ++k) {
                auto seed = compute_seed(pk, static_cast<uint16_t>(t),
                                            static_cast<uint16_t>(k));
                auto [u1, u2, u3] = crypto::prng_u123(seed);
                if (is_selected(u1)) ++count;
            }
        }
    }
    return count;
}
