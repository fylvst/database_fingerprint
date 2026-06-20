/**
 * crypto_utils.cpp
 *
 * Implementation of cryptographic primitives using OpenSSL.
 */

#include "crypto_utils.h"

#include <cstring>
#include <stdexcept>

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace crypto {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Write a uint64_t in big-endian order into dst[0..7]
static void write_be64(uint8_t* dst, uint64_t val) {
    for (int i = 7; i >= 0; --i) {
        dst[i] = static_cast<uint8_t>(val & 0xFF);
        val >>= 8;
    }
}

/// Write a uint16_t in big-endian order into dst[0..1]
static void write_be16(uint8_t* dst, uint16_t val) {
    dst[0] = static_cast<uint8_t>((val >> 8) & 0xFF);
    dst[1] = static_cast<uint8_t>(val & 0xFF);
}

/// Read a uint32_t from 4 bytes in big-endian order
static uint32_t read_be32(const uint8_t* src) {
    return (static_cast<uint32_t>(src[0]) << 24) |
           (static_cast<uint32_t>(src[1]) << 16) |
           (static_cast<uint32_t>(src[2]) << 8)  |
           (static_cast<uint32_t>(src[3]));
}

// ---------------------------------------------------------------------------
// HMAC-MD5
// ---------------------------------------------------------------------------

Bytes16 hmac_md5(const std::vector<uint8_t>& key,
                 const std::vector<uint8_t>& message) {
    Bytes16 result{};
    unsigned int out_len = 0;

    uint8_t* ret = HMAC(
        EVP_md5(),
        key.data(),  static_cast<int>(key.size()),
        message.data(), static_cast<int>(message.size()),
        result.data(), &out_len
    );

    if (ret == nullptr || out_len != 16) {
        throw std::runtime_error("hmac_md5: OpenSSL HMAC-MD5 failed");
    }
    return result;
}

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------

Bytes32 hmac_sha256(const std::vector<uint8_t>& key,
                    const std::vector<uint8_t>& message) {
    Bytes32 result{};
    unsigned int out_len = 0;

    uint8_t* ret = HMAC(
        EVP_sha256(),
        key.data(),  static_cast<int>(key.size()),
        message.data(), static_cast<int>(message.size()),
        result.data(), &out_len
    );

    if (ret == nullptr || out_len != 32) {
        throw std::runtime_error("hmac_sha256: OpenSSL HMAC-SHA256 failed");
    }
    return result;
}

// ---------------------------------------------------------------------------
// PRNG: AES-128-CTR → (U1, U2, U3)
// ---------------------------------------------------------------------------

PrngOutputs prng_u123(const Bytes16& seed) {
    // ASSUMPTION: Use AES-128-CTR with seed as key, nonce = 0.
    // Encrypt 12 zero bytes to get 12 bytes of keystream.
    // Split into 3 × uint32_t (big-endian).
    //
    // EVP_aes_128_ctr with a 16-byte IV set to all zeros.

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("prng_u123: EVP_CIPHER_CTX_new failed");
    }

    // IV = 16 zero bytes (CTR nonce)
    static const uint8_t zero_iv[16] = {};

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr,
                           seed.data(), zero_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("prng_u123: EVP_EncryptInit_ex failed");
    }

    // Plaintext: 12 zero bytes
    static const uint8_t zero_plain[12] = {};
    uint8_t keystream[12] = {};
    int out_len = 0;

    if (EVP_EncryptUpdate(ctx, keystream, &out_len,
                          zero_plain, 12) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("prng_u123: EVP_EncryptUpdate failed");
    }

    EVP_CIPHER_CTX_free(ctx);

    PrngOutputs out{};
    out.u1 = read_be32(keystream + 0);
    out.u2 = read_be32(keystream + 4);
    out.u3 = read_be32(keystream + 8);
    return out;
}

// ---------------------------------------------------------------------------
// Seed construction
// ---------------------------------------------------------------------------

Bytes16 make_seed(const std::vector<uint8_t>& owner_key,
                  uint64_t primary_key,
                  uint16_t t,
                  uint16_t k) {
    // message = uint64_be(primary_key) || uint16_be(t) || uint16_be(k)
    // total: 8 + 2 + 2 = 12 bytes
    uint8_t msg[12];
    write_be64(msg + 0, primary_key);
    write_be16(msg + 8, t);
    write_be16(msg + 10, k);

    std::vector<uint8_t> message(msg, msg + 12);
    Bytes32 digest = hmac_sha256(owner_key, message);

    // Truncate to first 16 bytes for AES-128 key
    Bytes16 seed{};
    std::copy(digest.begin(), digest.begin() + 16, seed.begin());
    return seed;
}

}  // namespace crypto
