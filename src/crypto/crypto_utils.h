#pragma once
/**
 * crypto_utils.h
 *
 * Cryptographic primitives used by the fingerprinting mechanism.
 *
 * Paper reference: Ji et al., NDSS 2023, Section IV-B
 *
 * Two operations are needed:
 *   1. HMAC-MD5(key, message) → 16 bytes (128-bit fingerprint)
 *      Paper: "f = HMAC_Y(ID_internal)"
 *      Paper footnote 2: "We use MD5 to generate a 128-bits fingerprint string"
 *
 *   2. Deterministic seed → (U1, U2, U3) three independent pseudorandom uint32_t
 *      Paper: "U is a cryptographic pseudorandom sequence generator"
 *      Paper: "U1(s), U2(s), U3(s) are the 1st, 2nd, 3rd outputs"
 *      ASSUMPTION: We use AES-128-CTR as the CSPRNG. Feed the 16-byte seed
 *      as the AES key, use zero nonce, encrypt 12 zero bytes → 12 bytes →
 *      split into three uint32_t (big-endian). This is a standard approach
 *      consistent with "computationally prohibitive to compute next number
 *      without knowing the seed" (paper p.12).
 *
 *   3. Seed construction: s = Y || r_i.PrimaryKey || t || k
 *      ASSUMPTION: Y is prepended as HMAC key in the seed HMAC call.
 *      Encoding: PK as 8-byte big-endian uint64, t as 2-byte big-endian uint16,
 *      k as 2-byte big-endian uint16. Concatenated as message to HMAC-SHA256(Y, ·).
 *      This avoids ambiguity between field boundaries.
 */

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace crypto {

/// 16-byte (128-bit) buffer — used as both fingerprint storage and AES seed
using Bytes16 = std::array<uint8_t, 16>;

/// 32-byte buffer — used for SHA-256 output
using Bytes32 = std::array<uint8_t, 32>;

/**
 * Compute HMAC-MD5(key, message) → 16 bytes.
 *
 * Used for fingerprint generation:
 *   f = HMAC_Y(ID_internal)   (paper Section IV-B, footnote 2)
 *
 * @param key      Owner secret key Y (arbitrary length)
 * @param message  ID_internal as raw bytes
 * @return         16-byte HMAC-MD5 digest = fingerprint bit-string
 */
Bytes16 hmac_md5(const std::vector<uint8_t>& key,
                 const std::vector<uint8_t>& message);

/**
 * Compute HMAC-SHA256(key, message) → 32 bytes.
 *
 * Used for:
 *   - Deriving per-SP sub-keys K_c = HMAC_Y("SP_KEY_" || id_external)
 *   - Computing the 16-byte AES seed from (Y, PK, t, k)
 *     seed = HMAC_SHA256(key=Y, msg=PK_bytes||t_bytes||k_bytes)[:16]
 *
 * ASSUMPTION: Truncating SHA-256 HMAC to 128 bits for the AES seed is
 * standard practice (NIST SP 800-56C). Security level: 128 bits.
 *
 * @param key      Arbitrary-length key
 * @param message  Arbitrary-length message
 * @return         32-byte HMAC-SHA256 digest
 */
Bytes32 hmac_sha256(const std::vector<uint8_t>& key,
                    const std::vector<uint8_t>& message);

/**
 * Deterministic PRNG: given a 16-byte seed, produce three independent
 * pseudorandom uint32_t values (U1, U2, U3).
 *
 * Implementation: AES-128-CTR(key=seed, nonce=0) applied to 12 zero bytes
 * yields 12 bytes of keystream, split as:
 *   U1 = bytes[0..3]  (big-endian)
 *   U2 = bytes[4..7]  (big-endian)
 *   U3 = bytes[8..11] (big-endian)
 *
 * ASSUMPTION: AES-CTR is used as the CSPRNG. The paper says U is a
 * "cryptographic pseudorandom sequence generator" but does not name a
 * specific algorithm. AES-CTR is the standard choice.
 *
 * @param seed  16-byte seed s = first 16 bytes of HMAC-SHA256(Y, PK||t||k)
 * @return      (U1, U2, U3) — three independent 32-bit pseudorandom values
 */
struct PrngOutputs {
    uint32_t u1;
    uint32_t u2;
    uint32_t u3;
};

PrngOutputs prng_u123(const Bytes16& seed);

/**
 * Build the 16-byte deterministic seed for position (primary_key, t, k).
 *
 * Paper: s = Y | r_i.PrimaryKey | t | k
 * where | is the concatenation operator.
 *
 * ASSUMPTION: Encoding is:
 *   message = uint64_be(primary_key) || uint16_be(t) || uint16_be(k)
 *   seed    = HMAC-SHA256(key=owner_key, msg=message)[:16]
 *
 * This provides:
 *   - Uniqueness: different (PK, t, k) give different seeds
 *   - Secrecy: seed is unpredictable without owner_key Y
 *   - Determinism: same inputs always give same seed
 *
 * @param owner_key   Secret key Y of the database owner
 * @param primary_key r_i.PrimaryKey (uint64)
 * @param t           Attribute index (0-indexed)
 * @param k           Bit index (1-indexed from LSB)
 * @return            16-byte seed
 */
Bytes16 make_seed(const std::vector<uint8_t>& owner_key,
                  uint64_t primary_key,
                  uint16_t t,
                  uint16_t k);

}  // namespace crypto
