#pragma once
/**
 * fingerprint_inserter.h
 *
 * FingerprintInserter: implements Algorithm 1 from the paper.
 *
 * Paper: Ji et al., NDSS 2023, Section IV-B (p.11)
 *
 * Algorithm 1 summary:
 *   For each bit position r^i_{t,k} in the fingerprintable set P:
 *     1. Set seed: s = Y | r_i.PrimaryKey | t | k
 *     2. Select this position if U1(s) mod floor(1/(2p)) == 0
 *     3. Mask bit: x = U2(s) % 2
 *     4. Fingerprint index: l = U3(s) % L
 *     5. Mark bit: B = x XOR f[l]
 *     6. Modify bit: r^i_{t,k} ← r^i_{t,k} XOR B
 *
 * Key distinction from prior work (Remark 2, paper p.12):
 *   Prior works: new_bit = x XOR f[l]   (independent of original bit)
 *   This paper:  new_bit = r^i_{t,k} XOR B   (dependent on original → enables DP proof)
 *
 * Privacy guarantee: Theorem 2 (paper p.11):
 *   The above scheme satisfies ε-entry-level DP because the selection probability ≥ 2p
 *   and Pr(B=1) ≥ p, satisfying the condition in Theorem 1.
 */

#include "../crypto/crypto_utils.h"
#include "types.h"

#include <cstdint>
#include <string>
#include <vector>

/**
 * Implements Algorithm 1: ε-Entry-Level DP Fingerprint Insertion.
 *
 * Thread-safe: stateless after construction (all state in params/key).
 */
class FingerprintInserter {
public:
    /**
     * @param params      All fingerprinting parameters (K, p, L, etc.)
     * @param owner_secret  Owner's secret key Y
     */
    FingerprintInserter(const FingerprintParams& params,
                        const std::vector<uint8_t>& owner_secret);

    /**
     * Algorithm 1: Insert fingerprint fp into database db.
     *
     * Produces a fingerprinted copy M(R). The original db is not modified.
     *
     * @param db           Original relational database R
     * @param fp           Fingerprint bit-string f (from FingerprintGenerator)
     * @param id_internal  SP's internal ID (used only for documentation; the
     *                     actual fingerprint selection uses owner_secret + PK)
     * @return             Fingerprinted copy M(R)
     */
    RelationalDatabase insert(const RelationalDatabase& db,
                              const Fingerprint& fp,
                              const std::string& id_internal) const;

    /**
     * Compute fingerprint density ‖M(R) - R‖_{1,1} without storing M(R).
     *
     * Used by PrivacyBudgetManager (Algorithm 3) to check density > Γ.
     * Runs the same inner loop as insert() but only accumulates the L1 norm.
     *
     * @return  Non-negative fingerprint density
     */
    double compute_density(const RelationalDatabase& db,
                           const Fingerprint& fp) const;

    /**
     * Returns a description of which positions would be selected.
     * Useful for debugging and unit tests.
     *
     * @return  Number of positions that satisfy the selection condition
     */
    size_t count_selected_positions(const RelationalDatabase& db) const;

private:
    FingerprintParams    params_;
    std::vector<uint8_t> owner_secret_;

    // -------------------------------------------------------------------------
    // Inner loop helpers (all const / pure)
    // -------------------------------------------------------------------------

    /**
     * Compute the 16-byte AES seed for position (primary_key, t, k).
     *
     * Paper: s = Y | r_i.PrimaryKey | t | k
     * Implementation: see crypto::make_seed
     */
    crypto::Bytes16 compute_seed(uint64_t primary_key,
                                  uint16_t t,
                                  uint16_t k) const;

    /**
     * Determine if this bit position is selected for fingerprinting.
     *
     * Paper: "if U1(s) mod floor(1/(2p)) == 0"
     *
     * Selection probability = 1 / floor(1/(2p)) ≈ 2p.
     * Paper footnote 3: "the probability of a specific bit position being
     *   fingerprinted is 2p"
     *
     * @param u1  First PRNG output U1(s)
     * @return    true if this position is selected
     */
    bool is_selected(uint32_t u1) const;

    /**
     * Compute mask bit x.
     *
     * Paper: "the database owner decides the value of mask bit x by checking
     *   if U2(s) is even or odd"
     *
     * x = 0 if U2 is even, x = 1 if U2 is odd.
     * Pr(x=0) = Pr(x=1) = 1/2 (uniform).
     *
     * @param u2  Second PRNG output U2(s)
     * @return    0 or 1
     */
    int compute_mask_bit(uint32_t u2) const;

    /**
     * Compute fingerprint index l.
     *
     * Paper: "sets the fingerprint index l = U3(s) mod L"
     *
     * @param u3  Third PRNG output U3(s)
     * @return    l ∈ [0, L-1]
     */
    int compute_fp_index(uint32_t u3) const;

    /**
     * Compute mark bit B.
     *
     * Paper: "it obtains the mark bit as B = x XOR f_l"
     *
     * Because x ~ Uniform{0,1} and is independent of f_l:
     *   Pr(B=1) = Pr(x=0)*Pr(f[l]=1) + Pr(x=1)*Pr(f[l]=0)
     *           = 0.5 * anything + 0.5 * anything = 0.5
     * But the effective flip probability (conditioned on selection) is ≥ p
     * per Theorem 2 proof.
     *
     * @param x    Mask bit (0 or 1)
     * @param f_l  l-th bit of fingerprint (0 or 1)
     * @return     B = x XOR f_l ∈ {0, 1}
     */
    int compute_mark_bit(int x, int f_l) const;

    /**
     * Apply the bit modification.
     *
     * Paper: "changes the bit value of r^i_{t,k} with r^i_{t,k} XOR B"
     *
     * This is the KEY DISTINCTION from prior work:
     *   - Prior work: new_bit = x XOR f_l  (replaces original, loses dependency)
     *   - This paper: new_bit = original_bit XOR B  (preserves dependency on original)
     *
     * The dependency on the original bit is what allows the DP proof in Theorem 1
     * (the probability ratio is bounded by e^ε).
     *
     * @param original_bit  r^i_{t,k} ∈ {0, 1}
     * @param B             Mark bit ∈ {0, 1}
     * @return              New bit value = original_bit XOR B
     */
    int apply_mark(int original_bit, int B) const;
};
