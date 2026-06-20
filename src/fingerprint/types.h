#pragma once
/**
 * types.h
 *
 * Core data types shared across all fingerprinting modules.
 *
 * Paper: Ji et al., NDSS 2023 — Section III (Definitions) and Section IV
 */

#include <array>
#include <cmath>
#include <cstdint>
#include <string>
#include <vector>
#include <stdexcept>

// ============================================================================
// Fingerprint bit-string
// ============================================================================

/**
 * A 128-bit fingerprint bit-string.
 *
 * Paper: "We use MD5 to generate a 128-bits fingerprint string" (footnote 2)
 * f = HMAC_Y(ID_internal)
 *
 * Bit indexing: l ∈ [0, 127]
 *   Byte layout: bit l is at byte (l/8), bit position (7 - l%8) within that byte
 *   (MSB-first within each byte)
 */
struct Fingerprint {
    static constexpr int LENGTH_BITS = 128;
    static constexpr int LENGTH_BYTES = 16;

    std::array<uint8_t, 16> data{};

    /// Get bit at index l ∈ [0, 127]. Returns 0 or 1.
    int get_bit(int l) const {
        if (l < 0 || l >= LENGTH_BITS) throw std::out_of_range("Fingerprint::get_bit");
        return (data[l / 8] >> (7 - l % 8)) & 1;
    }

    /// Set bit at index l to val (0 or 1).
    void set_bit(int l, int val) {
        if (l < 0 || l >= LENGTH_BITS) throw std::out_of_range("Fingerprint::set_bit");
        if (val) {
            data[l / 8] |= static_cast<uint8_t>(1 << (7 - l % 8));
        } else {
            data[l / 8] &= static_cast<uint8_t>(~(1 << (7 - l % 8)));
        }
    }

    /// Count matching bits between two fingerprints.
    int bit_matches(const Fingerprint& other) const {
        int count = 0;
        for (int i = 0; i < LENGTH_BYTES; ++i) {
            uint8_t xor_val = data[i] ^ other.data[i];
            // Count zeros (matches) = 8 - popcount(xor)
            count += 8 - __builtin_popcount(xor_val);
        }
        return count;
    }

    bool operator==(const Fingerprint& o) const { return data == o.data; }
    bool operator!=(const Fingerprint& o) const { return data != o.data; }
};

// ============================================================================
// AttributeDomain: metadata for one column
// ============================================================================

/**
 * Describes the integer domain of one database attribute.
 *
 * Paper: The mechanism operates on integer-encoded attributes.
 * "We assume that the k-th to the last bit of an entry is its k-th insignificant bit."
 * (Section IV-A)
 *
 * K_t = number of bits used to encode this attribute
 * Paper: min(K, K_t) bits per attribute are in the fingerprintable set P
 */
struct AttributeDomain {
    std::string name;       ///< Human-readable column name
    int32_t     min_val;    ///< Minimum integer value in domain
    int32_t     max_val;    ///< Maximum integer value in domain

    /// K_t: bits needed to encode max_val - min_val
    /// ASSUMPTION: K_t = ceil(log2(max_val - min_val + 1)), minimum 1.
    int num_bits() const {
        int range = max_val - min_val;
        if (range <= 0) return 1;
        return static_cast<int>(std::ceil(std::log2(range + 1)));
    }

    bool fingerprint;   ///< Whether this attribute participates in fingerprinting.
                        ///< ASSUMPTION: Label/target columns are excluded by caller.
                        ///< Primary key column is always excluded.
};

// ============================================================================
// Record: a single database row
// ============================================================================

/**
 * One data record in the relational database.
 *
 * Paper: "Each data record is also associated with a primary key, which is used
 * to uniquely identify that record." (Definition 1)
 * "The primary keys should not be changed if a database is fingerprinted." (Section III)
 *
 * attributes[t] is the integer-encoded value of the t-th non-PK attribute (0-indexed).
 */
struct Record {
    uint64_t             primary_key;   ///< r_i.PrimaryKey — immutable, not fingerprinted
    std::vector<int32_t> attributes;    ///< T integer-encoded attribute values (0-indexed)
};

// ============================================================================
// RelationalDatabase
// ============================================================================

/**
 * A relational database with N records and T fingerprintable attributes.
 *
 * Paper Definition 1: "A relational database denoted as R is a collection of
 * T-tuples. Each tuple represents a data record containing T ordered attributes."
 *
 * Note: T here refers to the number of NON-primary-key attributes.
 */
struct RelationalDatabase {
    std::vector<Record>          records;   ///< N records
    std::vector<AttributeDomain> domains;   ///< T attribute domains (parallel to attributes)

    size_t num_records()    const { return records.size(); }
    size_t num_attributes() const { return domains.size(); }

    /**
     * Get the k-th least significant bit (k is 1-indexed) of attribute t of record i.
     *
     * Paper: r^i_{t,k} = k-th insignificant bit of attribute t of record r^i
     * "the k-th to the last bit of an entry is its k-th insignificant bit"
     *
     * k=1 → LSB (bit 0), k=2 → bit 1, etc.
     *
     * @return 0 or 1
     */
    int get_bit(size_t record_idx, size_t attr_idx, int k) const;

    /**
     * Set the k-th least significant bit of attribute t of record i.
     * k=1 → LSB.
     */
    void set_bit(size_t record_idx, size_t attr_idx, int k, int bit_val);

    /**
     * Compute the L1,1 fingerprint density against the original database.
     *
     * Paper Corollary 1: ‖M(R) - R‖_{1,1} = sum of absolute differences
     */
    double fingerprint_density(const RelationalDatabase& original) const;

    /**
     * Post-process: clip all attribute values to their valid domain range.
     *
     * Paper Section VII-A: "post-process the resulting database M(R) to eliminate
     * entries that are not in the original domain."
     * This is valid due to DP post-processing immunity.
     */
    void clip_to_domain();
};

// ============================================================================
// FingerprintParams: all algorithm parameters
// ============================================================================

/**
 * All tunable parameters for the fingerprinting mechanism.
 *
 * Derived from epsilon and sensitivity per Theorem 1:
 *   K = ceil(log2(Δ)) + 1
 *   p = 1 / (exp(ε/K) + 1)
 */
struct FingerprintParams {
    double  epsilon;        ///< Privacy budget ε > 0
    int32_t sensitivity;    ///< Δ = database sensitivity (max pairwise entry diff)
    int     K;              ///< Number of LSBs per entry: K = ceil(log2(Δ)) + 1
    double  p;              ///< Flip probability: p = 1 / (e^(ε/K) + 1)
    int     L;              ///< Fingerprint length in bits (= 128, MD5 output)
    int     C;              ///< Number of SPs (used for threshold D)
    int     D;              ///< Bit-match threshold for accusation

    /**
     * Construct params from epsilon and sensitivity.
     * Derives K, p automatically per Theorem 1.
     *
     * @param epsilon      ε > 0, privacy budget
     * @param sensitivity  Δ ≥ 1
     * @param C            Number of SPs (for computing D)
     */
    static FingerprintParams from_epsilon(double epsilon,
                                          int32_t sensitivity,
                                          int C);

    /**
     * Compute the detection threshold D.
     *
     * Paper Appendix C: find minimum D s.t. C(L, D) * (1/2)^D * (1/2)^(L-D) ≥ 1/C
     * Equivalently: sum_{d=D}^{L} C(L,d) / 2^L ≥ 1/C
     *
     * ASSUMPTION: We use a simple numerical search over D ∈ [L/2, L].
     */
    static int compute_detection_threshold(int L, int C);
};

// ============================================================================
// ExtractionResult: output of Algorithm 2
// ============================================================================

struct ExtractionResult {
    Fingerprint        extracted_fp;            ///< f_hat after majority vote
    std::vector<int>   c0;                      ///< c0[l]: times bit l decoded as 0
    std::vector<int>   c1;                      ///< c1[l]: times bit l decoded as 1
    int                num_positions_processed; ///< Total selected positions found
    int                num_records_matched;     ///< Records in both leaked & original
};
