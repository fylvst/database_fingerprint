/**
 * test_crypto.cpp — Unit tests for crypto_utils
 */
#include "test_framework.h"
#include "../src/crypto/crypto_utils.h"
#include <cstring>
#include <vector>

static std::vector<uint8_t> sv(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

void run_crypto_tests() {

    run_test("hmac_md5_output_is_16_bytes", [] {
        auto d = crypto::hmac_md5(sv("key"), sv("msg"));
        ASSERT_EQ(d.size(), 16u);
    });

    run_test("hmac_md5_deterministic", [] {
        auto k = sv("secret_key_Y"); auto m = sv("id_internal_001");
        ASSERT_TRUE(crypto::hmac_md5(k,m) == crypto::hmac_md5(k,m));
    });

    run_test("hmac_md5_key_sensitivity", [] {
        auto m = sv("msg");
        ASSERT_TRUE(crypto::hmac_md5(sv("k1"),m) != crypto::hmac_md5(sv("k2"),m));
    });

    run_test("hmac_md5_message_sensitivity", [] {
        auto k = sv("key");
        ASSERT_TRUE(crypto::hmac_md5(k,sv("m1")) != crypto::hmac_md5(k,sv("m2")));
    });

    run_test("hmac_sha256_output_is_32_bytes", [] {
        auto d = crypto::hmac_sha256(sv("key"), sv("msg"));
        ASSERT_EQ(d.size(), 32u);
    });

    run_test("hmac_sha256_deterministic", [] {
        auto k = sv("owner"); auto m = sv("SP_KEY_1");
        ASSERT_TRUE(crypto::hmac_sha256(k,m) == crypto::hmac_sha256(k,m));
    });

    run_test("hmac_sha256_key_sensitivity", [] {
        auto m = sv("msg");
        ASSERT_TRUE(crypto::hmac_sha256(sv("k1"),m) != crypto::hmac_sha256(sv("k2"),m));
    });

    run_test("prng_deterministic", [] {
        crypto::Bytes16 seed{}; seed[0]=0xAB; seed[15]=0xEF;
        auto r1 = crypto::prng_u123(seed);
        auto r2 = crypto::prng_u123(seed);
        ASSERT_EQ(r1.u1, r2.u1); ASSERT_EQ(r1.u2, r2.u2); ASSERT_EQ(r1.u3, r2.u3);
    });

    run_test("prng_seed_sensitivity", [] {
        crypto::Bytes16 s1{}; s1[0]=0x01;
        crypto::Bytes16 s2{}; s2[0]=0x02;
        auto r1 = crypto::prng_u123(s1);
        auto r2 = crypto::prng_u123(s2);
        bool any_diff = (r1.u1!=r2.u1)||(r1.u2!=r2.u2)||(r1.u3!=r2.u3);
        ASSERT_TRUE(any_diff);
    });

    run_test("prng_u1u2u3_not_all_equal_across_seeds", [] {
        // At least 9/10 seeds should produce non-all-equal (U1,U2,U3)
        int all_eq = 0;
        for (uint8_t b = 0; b < 10; ++b) {
            crypto::Bytes16 s{}; s[0]=b; s[7]=(uint8_t)(b*13);
            auto r = crypto::prng_u123(s);
            if (r.u1==r.u2 && r.u2==r.u3) ++all_eq;
        }
        ASSERT_TRUE(all_eq < 2);
    });

    run_test("make_seed_is_16_bytes", [] {
        auto s = crypto::make_seed(sv("k"), 1ULL, 0, 1);
        ASSERT_EQ(s.size(), 16u);
    });

    run_test("make_seed_deterministic", [] {
        auto k = sv("owner_key");
        ASSERT_TRUE(crypto::make_seed(k,42,3,2) == crypto::make_seed(k,42,3,2));
    });

    run_test("make_seed_pk_sensitivity", [] {
        auto k = sv("owner_key");
        ASSERT_TRUE(crypto::make_seed(k,1,0,1) != crypto::make_seed(k,2,0,1));
    });

    run_test("make_seed_t_sensitivity", [] {
        auto k = sv("owner_key");
        ASSERT_TRUE(crypto::make_seed(k,1,0,1) != crypto::make_seed(k,1,1,1));
    });

    run_test("make_seed_k_sensitivity", [] {
        auto k = sv("owner_key");
        ASSERT_TRUE(crypto::make_seed(k,1,0,1) != crypto::make_seed(k,1,0,2));
    });

    run_test("make_seed_owner_key_sensitivity", [] {
        ASSERT_TRUE(crypto::make_seed(sv("k1"),1,0,1) != crypto::make_seed(sv("k2"),1,0,1));
    });
}
