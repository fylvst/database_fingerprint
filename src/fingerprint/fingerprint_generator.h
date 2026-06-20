#pragma once
/**
 * fingerprint_generator.h
 *
 * FingerprintGenerator: generates the 128-bit fingerprint bit-string for an SP.
 *
 * Paper: Ji et al., NDSS 2023, Section IV-B:
 *   "the database owner generates the unique fingerprint for this SP via
 *    f = HMAC_Y | ID_internal"
 *   "Y is the secret key of the database owner"
 *   Footnote 2: "We use MD5 to generate a 128-bits fingerprint string"
 *
 * Key derivation hierarchy:
 *   master_key Y
 *     └─ per-SP key K_c = HMAC_SHA256(Y, "SP_KEY_" || id_external)
 *          └─ ID_internal = HMAC_SHA256(K_c, trial_number_bytes)
 *               └─ fingerprint f = HMAC_MD5(Y, ID_internal)
 *
 * ASSUMPTION (key hierarchy): The paper says f = HMAC_Y(ID_internal) where Y
 * is the secret key. It also says ID_internal is generated via Hash(K_c, i).
 * We use HMAC-SHA256 for all intermediate steps and HMAC-MD5 for the final
 * fingerprint (to get exactly 128 bits, per footnote 2).
 *
 * ASSUMPTION (ID_internal format): We represent ID_internal as a 32-byte
 * hex string of the HMAC-SHA256 output, then feed that as UTF-8 bytes into
 * the final HMAC-MD5. This is human-readable and collision-resistant.
 */

#include "../crypto/crypto_utils.h"
#include "types.h"

#include <cstdint>
#include <string>
#include <vector>

/**
 * Generates fingerprints (f) and internal IDs for service providers.
 *
 * Thread-safe: all methods are const and stateless after construction.
 */
class FingerprintGenerator {
public:
    /**
     * Construct with the database owner's secret key Y.
     *
     * @param owner_secret  Y: the owner's master secret key (arbitrary bytes).
     *                      ASSUMPTION: minimum 16 bytes recommended for security.
     */
    explicit FingerprintGenerator(const std::vector<uint8_t>& owner_secret);

    /**
     * Generate the 128-bit fingerprint for an SP given its internal ID.
     *
     * Paper: f = HMAC_Y(ID_internal)
     * Implementation: HMAC-MD5(key=owner_secret, msg=id_internal_bytes)
     *
     * @param id_internal  The internal ID string for this SP (from generate_internal_id)
     * @return             128-bit fingerprint as Fingerprint struct
     */
    Fingerprint generate(const std::string& id_internal) const;

    /**
     * Derive a per-SP sub-key K_c from the owner key Y and the SP's external ID.
     *
     * ASSUMPTION: K_c = HMAC-SHA256(key=owner_secret, msg="SP_KEY_" || uint64_be(id_external))
     * This binds K_c to both the owner key and the specific SP identity.
     *
     * @param id_external  Publicly known SP identifier
     * @return             32-byte per-SP key K_c
     */
    std::vector<uint8_t> derive_sp_key(uint64_t id_external) const;

    /**
     * Generate the i-th candidate internal ID for the SP with key sp_key.
     *
     * Paper: ID_internal_c = Hash(K_c, i)
     * Implementation: HMAC-SHA256(key=sp_key, msg=uint32_be(trial)) → hex string
     *
     * The trial counter i is 1-indexed per Algorithm 3 (line 5 in paper).
     *
     * ASSUMPTION: We encode the trial number as a 4-byte big-endian integer.
     * The output is hex-encoded to produce a printable ID string.
     *
     * @param sp_key  Per-SP key K_c (from derive_sp_key)
     * @param trial   Trial number i (1-indexed)
     * @return        32-character hex string usable as ID_internal
     */
    std::string generate_internal_id(const std::vector<uint8_t>& sp_key,
                                     int trial) const;

    /**
     * Convenience: derive K_c and generate ID_internal in one step.
     *
     * @param id_external  Publicly known SP identifier
     * @param trial        Trial number (1-indexed)
     * @return             (id_internal_string, sp_key)
     */
    std::pair<std::string, std::vector<uint8_t>>
    derive_and_generate(uint64_t id_external, int trial) const;

private:
    std::vector<uint8_t> owner_secret_;  ///< Y: owner's master secret key

    /// Convert bytes to hex string (lowercase)
    static std::string to_hex(const uint8_t* data, size_t len);

    /// Encode uint64 as 8-byte big-endian
    static std::array<uint8_t, 8> encode_be64(uint64_t val);

    /// Encode uint32 as 4-byte big-endian
    static std::array<uint8_t, 4> encode_be32(uint32_t val);
};
