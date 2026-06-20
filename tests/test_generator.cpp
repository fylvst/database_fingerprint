/**
 * test_generator.cpp — Unit tests for FingerprintGenerator
 */
#include "test_framework.h"
#include "../src/fingerprint/fingerprint_generator.h"
#include <stdexcept>

static std::vector<uint8_t> K(const std::string& s) {
    return {s.begin(), s.end()};
}

void run_generator_tests() {

    run_test("gen_output_is_128_bits", [] {
        FingerprintGenerator g(K("secret_owner_key"));
        auto fp = g.generate("id_001");
        ASSERT_EQ(fp.LENGTH_BITS, 128);
    });

    run_test("gen_deterministic", [] {
        FingerprintGenerator g(K("secret_owner_key"));
        ASSERT_TRUE(g.generate("id_001") == g.generate("id_001"));
    });

    run_test("gen_id_sensitivity", [] {
        FingerprintGenerator g(K("key"));
        ASSERT_TRUE(g.generate("id_001") != g.generate("id_002"));
    });

    run_test("gen_key_sensitivity", [] {
        ASSERT_TRUE(
            FingerprintGenerator(K("key_alice")).generate("same_id") !=
            FingerprintGenerator(K("key_bob")).generate("same_id"));
    });

    run_test("gen_nonzero_output", [] {
        FingerprintGenerator g(K("owner_key_for_test"));
        auto fp = g.generate("some_id_internal");
        bool has0=false, has1=false;
        for (int l=0;l<128;++l) {
            if (fp.get_bit(l)==1) has1=true;
            if (fp.get_bit(l)==0) has0=true;
        }
        ASSERT_TRUE(has0); ASSERT_TRUE(has1);
    });

    run_test("gen_sp_key_deterministic", [] {
        FingerprintGenerator g(K("owner_key"));
        ASSERT_TRUE(g.derive_sp_key(42ULL) == g.derive_sp_key(42ULL));
    });

    run_test("gen_sp_key_id_sensitivity", [] {
        FingerprintGenerator g(K("owner_key"));
        ASSERT_TRUE(g.derive_sp_key(1ULL) != g.derive_sp_key(2ULL));
    });

    run_test("gen_sp_key_length_32", [] {
        FingerprintGenerator g(K("owner_key"));
        ASSERT_EQ(g.derive_sp_key(1ULL).size(), 32u);
    });

    run_test("gen_internal_id_deterministic", [] {
        FingerprintGenerator g(K("owner_key"));
        auto k = g.derive_sp_key(1ULL);
        ASSERT_TRUE(g.generate_internal_id(k,1) == g.generate_internal_id(k,1));
    });

    run_test("gen_internal_id_trial_sensitivity", [] {
        FingerprintGenerator g(K("owner_key"));
        auto k = g.derive_sp_key(1ULL);
        ASSERT_TRUE(g.generate_internal_id(k,1) != g.generate_internal_id(k,2));
        ASSERT_TRUE(g.generate_internal_id(k,1) != g.generate_internal_id(k,3));
    });

    run_test("gen_internal_id_invalid_trial_throws", [] {
        FingerprintGenerator g(K("owner_key"));
        auto k = g.derive_sp_key(1ULL);
        bool threw = false;
        try { g.generate_internal_id(k, 0); }
        catch (const std::invalid_argument&) { threw = true; }
        ASSERT_TRUE(threw);
    });

    run_test("gen_per_sp_isolation", [] {
        FingerprintGenerator g(K("owner_key"));
        auto k1 = g.derive_sp_key(1ULL);
        auto k2 = g.derive_sp_key(2ULL);
        auto id1 = g.generate_internal_id(k1,1);
        auto id2 = g.generate_internal_id(k2,1);
        ASSERT_TRUE(id1 != id2);
        ASSERT_TRUE(g.generate(id1) != g.generate(id2));
    });

    run_test("gen_empty_key_throws", [] {
        bool threw = false;
        try { FingerprintGenerator g({}); }
        catch (const std::invalid_argument&) { threw = true; }
        ASSERT_TRUE(threw);
    });
}
