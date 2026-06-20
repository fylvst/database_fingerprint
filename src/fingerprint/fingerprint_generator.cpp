/**
 * fingerprint_generator.cpp
 *
 * Implementation of FingerprintGenerator.
 */

#include "fingerprint_generator.h"

#include <iomanip>
#include <sstream>
#include <stdexcept>

// ============================================================================
// Constructor
// ============================================================================

FingerprintGenerator::FingerprintGenerator(const std::vector<uint8_t>& owner_secret)
    : owner_secret_(owner_secret) {
    if (owner_secret.empty()) {
        throw std::invalid_argument("FingerprintGenerator: owner_secret must not be empty");
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

std::string FingerprintGenerator::to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::array<uint8_t, 8> FingerprintGenerator::encode_be64(uint64_t val) {
    std::array<uint8_t, 8> buf{};
    for (int i = 7; i >= 0; --i) {
        buf[i] = static_cast<uint8_t>(val & 0xFF);
        val >>= 8;
    }
    return buf;
}

std::array<uint8_t, 4> FingerprintGenerator::encode_be32(uint32_t val) {
    std::array<uint8_t, 4> buf{};
    buf[0] = static_cast<uint8_t>((val >> 24) & 0xFF);
    buf[1] = static_cast<uint8_t>((val >> 16) & 0xFF);
    buf[2] = static_cast<uint8_t>((val >> 8)  & 0xFF);
    buf[3] = static_cast<uint8_t>(val & 0xFF);
    return buf;
}

// ============================================================================
// derive_sp_key
// ============================================================================

std::vector<uint8_t> FingerprintGenerator::derive_sp_key(uint64_t id_external) const {
    // K_c = HMAC-SHA256(key=owner_secret, msg="SP_KEY_" || uint64_be(id_external))
    //
    // ASSUMPTION: The prefix "SP_KEY_" (7 bytes) disambiguates this key derivation
    // from other HMAC uses with the same master key Y.
    const char* prefix = "SP_KEY_";
    std::vector<uint8_t> message(prefix, prefix + 7);

    auto id_bytes = encode_be64(id_external);
    message.insert(message.end(), id_bytes.begin(), id_bytes.end());

    auto digest = crypto::hmac_sha256(owner_secret_, message);
    return std::vector<uint8_t>(digest.begin(), digest.end());
}

// ============================================================================
// generate_internal_id
// ============================================================================

std::string FingerprintGenerator::generate_internal_id(
    const std::vector<uint8_t>& sp_key,
    int trial) const {

    if (trial < 1) throw std::invalid_argument("generate_internal_id: trial must be >= 1");

    // ID_internal = HMAC-SHA256(key=sp_key, msg=uint32_be(trial))
    // → take first 16 bytes → hex-encode to 32-char string
    //
    // ASSUMPTION: Using first 16 bytes (128 bits) of SHA-256 output for the ID.
    // This provides sufficient collision resistance for typical C values.
    auto trial_bytes = encode_be32(static_cast<uint32_t>(trial));
    std::vector<uint8_t> message(trial_bytes.begin(), trial_bytes.end());

    auto digest = crypto::hmac_sha256(sp_key, message);
    // Use the full 32 bytes for the ID string to maximize uniqueness
    return to_hex(digest.data(), digest.size());
}

// ============================================================================
// generate (core: f = HMAC_Y(ID_internal))
// ============================================================================

Fingerprint FingerprintGenerator::generate(const std::string& id_internal) const {
    // Paper: f = HMAC_Y(ID_internal)
    // Footnote 2: "We use MD5 to generate a 128-bits fingerprint string"
    //
    // Implementation: HMAC-MD5(key=owner_secret, msg=id_internal_as_utf8_bytes)

    std::vector<uint8_t> message(id_internal.begin(), id_internal.end());
    auto digest = crypto::hmac_md5(owner_secret_, message);

    Fingerprint fp{};
    std::copy(digest.begin(), digest.end(), fp.data.begin());
    return fp;
}

// ============================================================================
// derive_and_generate (convenience)
// ============================================================================

std::pair<std::string, std::vector<uint8_t>>
FingerprintGenerator::derive_and_generate(uint64_t id_external, int trial) const {
    auto sp_key      = derive_sp_key(id_external);
    auto id_internal = generate_internal_id(sp_key, trial);
    return {id_internal, sp_key};
}
