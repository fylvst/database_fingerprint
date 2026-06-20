#pragma once
/**
 * fingerprint_extractor.h
 *
 * FingerprintExtractor: implements Algorithm 2 from the paper.
 *
 * Paper: Ji et al., NDSS 2023, Section IV-C (p.12-13)
 *
 * Algorithm 2 summary:
 *   1. Initialize f = [?, ?, ..., ?]  (unknown)
 *      Initialize c0[l] = c1[l] = 0  for l ∈ [0, L-1]
 *
 *   2. For each bit position r^i_{t,k} in P̄ (from leaked database R̄):
 *      a. Recompute seed s = Y | r_i.PrimaryKey | t | k
 *      b. Check selection: if U1(s) mod floor(1/(2p)) == 0
 *      c. Recover mask bit:       x = U2(s) % 2
 *      d. Recover fp index:       l = U3(s) % L
 *      e. Recover mark bit:       B̂ = r̄^i_{t,k} XOR r^i_{t,k}
 *      f. Recover fp bit:         f̂_l = x XOR B̂
 *      g. Update counter:         c0[l]++ or c1[l]++
 *
 *   3. Majority vote:
 *      f̂[l] = 1 if c1[l] > c0[l], else f̂[l] = 0
 *
 * Key observation: The extractor needs BOTH the leaked R̄ and the original R.
 * It uses R to look up the original bit r^i_{t,k} for comparison.
 * Records are matched via primary key (which is preserved in R̄ per the paper's
 * assumption that primary keys are immutable).
 */

#include "../crypto/crypto_utils.h"
#include "types.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

/**
 * Implements Algorithm 2: Fingerprint Extraction with Majority Voting.
 *
 * Thread-safe: stateless after construction.
 */
class FingerprintExtractor {
public:
    /**
     * @param params      Fingerprinting parameters (must match those used in insertion)
     * @param owner_secret  Owner's secret key Y
     */
    FingerprintExtractor(const FingerprintParams& params,
                         const std::vector<uint8_t>& owner_secret);

    /**
     * Algorithm 2: Extract the embedded fingerprint from a leaked database.
     *
     * The leaked database R̄ is matched against the original R using primary keys.
     * Records present in R̄ but not in R are skipped (they cannot contribute
     * since we can't compute the mark bit without the original value).
     *
     * NOTE: Records missing from R̄ (subset attack) simply contribute fewer
     * votes but do not cause errors — the majority vote tolerates this.
     *
     * @param leaked    R̄: the leaked/pirated database (may be distorted)
     * @param original  R: the original database (owner's copy)
     * @return          ExtractionResult with extracted fingerprint and counters
     */
    ExtractionResult extract(const RelationalDatabase& leaked,
                             const RelationalDatabase& original) const;

    /**
     * After extraction, compare the extracted fingerprint against a known
     * fingerprint to count bit matches.
     *
     * Paper Section IV-C: "one of these SPs will be considered as guilty
     * if there is a large overlap between its fingerprint and the constructed one."
     * "the database owner can correctly identify the malicious SP as long as
     * the overlapping between fingerprints is above 50%"
     *
     * @param extracted  f̂ from extract()
     * @param candidate  Stored fingerprint f_j of SP j
     * @return           Number of matching bits (0..128)
     */
    static int count_bit_matches(const Fingerprint& extracted,
                                  const Fingerprint& candidate);

    /**
     * Identify the most likely traitor from a list of SP fingerprints.
     *
     * Returns the index of the SP with the most bit matches against f̂,
     * or -1 if no SP exceeds the detection threshold D.
     *
     * Paper: "the database owner compares the constructed fingerprint bit-string
     * with the fingerprint customized for each SP who has received the database"
     *
     * @param extracted      f̂ from extract()
     * @param sp_fingerprints  Stored fingerprints for each SP (index = SP index)
     * @param threshold_D    Minimum bit matches to accuse (from FingerprintParams::D)
     * @return               (accused_sp_index, max_matches), accused_sp_index=-1 if none
     */
    static std::pair<int, int> identify_traitor(
        const Fingerprint&              extracted,
        const std::vector<Fingerprint>& sp_fingerprints,
        int                             threshold_D);

private:
    FingerprintParams    params_;
    std::vector<uint8_t> owner_secret_;

    // -------------------------------------------------------------------------
    // Inner loop helpers
    // -------------------------------------------------------------------------

    /**
     * Build a map: primary_key → record_index, for fast lookup in original DB.
     * Used to match leaked records to original records.
     */
    std::unordered_map<uint64_t, size_t>
    build_pk_index(const RelationalDatabase& db) const;

    /**
     * Compute seed for position (primary_key, t, k). Same logic as inserter.
     */
    crypto::Bytes16 compute_seed(uint64_t primary_key,
                                  uint16_t t,
                                  uint16_t k) const;

    /**
     * Check if a position was selected for fingerprinting. Same logic as inserter.
     */
    bool is_selected(uint32_t u1) const;

    /**
     * Recover mask bit x from U2. Same logic as inserter.
     */
    int compute_mask_bit(uint32_t u2) const;

    /**
     * Recover fingerprint index l from U3. Same logic as inserter.
     */
    int compute_fp_index(uint32_t u3) const;

    /**
     * Recover the mark bit B̂ from a leaked bit and the original bit.
     *
     * Paper: "it recovers the mark bit as B = r̄^i_{t,k} XOR r^i_{t,k}"
     *
     * If no attack occurred: leaked_bit = original_bit XOR B → B̂ = B exactly.
     * If attacked (bit flipped): B̂ may differ from the original B.
     *
     * @param leaked_bit    r̄^i_{t,k} from the leaked database
     * @param original_bit  r^i_{t,k} from the original database
     * @return              B̂ = leaked_bit XOR original_bit ∈ {0, 1}
     */
    int recover_mark_bit(int leaked_bit, int original_bit) const;

    /**
     * Recover the fingerprint bit at index l.
     *
     * Paper: "fingerprint bit at index l as f_l = x XOR B"
     *
     * Using the recovered B̂: f̂_l = x XOR B̂
     * If B̂ == original B: f̂_l == f[l] exactly.
     * If B̂ ≠ B (attack): f̂_l is wrong for this position.
     *
     * @param x    Mask bit (recovered from U2)
     * @param B    Recovered mark bit
     * @return     f̂_l ∈ {0, 1}
     */
    int recover_fp_bit(int x, int B) const;

    /**
     * Apply majority voting to determine each fingerprint bit.
     *
     * Paper Section IV-C (p.13):
     *   "the database owner sets f_l = 1, if c1[l] > c0[l], otherwise f_l = 0"
     *
     * ASSUMPTION (tie-breaking): When c1[l] == c0[l], we set f̂[l] = 0.
     * The paper does not specify tie behavior. In practice, ties are rare
     * when enough bit positions encode each fingerprint bit.
     *
     * ASSUMPTION (zero-evidence): When c0[l] + c1[l] == 0 (no evidence for bit l,
     * e.g., severe subset attack removed all relevant rows), we set f̂[l] = 0.
     *
     * @param c0  Vote counts for bit=0, indexed by l
     * @param c1  Vote counts for bit=1, indexed by l
     * @return    Final fingerprint f̂
     */
    Fingerprint majority_vote(const std::vector<int>& c0,
                               const std::vector<int>& c1) const;
};
