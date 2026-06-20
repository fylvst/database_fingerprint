/**
 * test_types.cpp — Unit tests for Fingerprint, RelationalDatabase, FingerprintParams
 */
#include "test_framework.h"
#include "../src/fingerprint/types.h"
#include <cmath>
#include <stdexcept>

static RelationalDatabase make_small_db() {
    RelationalDatabase db;
    db.domains.resize(3);
    for (int t = 0; t < 3; ++t) {
        db.domains[t] = {"attr"+std::to_string(t), 0, 4, true};
    }
    for (uint64_t i = 0; i < 5; ++i) {
        Record r; r.primary_key = i+1;
        r.attributes = {(int32_t)i, (int32_t)(i+1), (int32_t)(i+2)};
        db.records.push_back(r);
    }
    return db;
}

void run_types_tests() {

    run_test("fingerprint_initial_all_zero", [] {
        Fingerprint fp{};
        for (int l = 0; l < 128; ++l) ASSERT_EQ(fp.get_bit(l), 0);
    });

    run_test("fingerprint_set_get_roundtrip", [] {
        Fingerprint fp{};
        for (int l = 0; l < 128; l+=2) fp.set_bit(l, 1);
        for (int l = 0; l < 128; ++l)
            ASSERT_EQ(fp.get_bit(l), l%2==0 ? 1 : 0);
    });

    run_test("fingerprint_bounds_throws", [] {
        Fingerprint fp{};
        bool t1=false, t2=false;
        try { fp.get_bit(-1); } catch (const std::out_of_range&) { t1=true; }
        try { fp.get_bit(128); } catch (const std::out_of_range&) { t2=true; }
        ASSERT_TRUE(t1); ASSERT_TRUE(t2);
    });

    run_test("fingerprint_bit_matches_identical", [] {
        Fingerprint a{}, b{};
        ASSERT_EQ(a.bit_matches(b), 128);
    });

    run_test("fingerprint_bit_matches_all_different", [] {
        Fingerprint a{}, b{};
        for (int i=0;i<16;++i) b.data[i]=0xFF;
        ASSERT_EQ(a.bit_matches(b), 0);
    });

    run_test("fingerprint_bit_matches_one_flip", [] {
        Fingerprint a{}, c{};
        c.set_bit(0,1);
        ASSERT_EQ(a.bit_matches(c), 127);
    });

    run_test("attr_domain_num_bits_delta1", [] {
        AttributeDomain d{"",0,1,true};
        ASSERT_EQ(d.num_bits(), 1);
    });

    run_test("attr_domain_num_bits_delta3", [] {
        AttributeDomain d{"",0,3,true};
        ASSERT_EQ(d.num_bits(), 2);
    });

    run_test("attr_domain_num_bits_delta4", [] {
        AttributeDomain d{"",0,4,true};
        ASSERT_EQ(d.num_bits(), 3);
    });

    run_test("attr_domain_num_bits_delta15", [] {
        AttributeDomain d{"",0,15,true};
        ASSERT_EQ(d.num_bits(), 4);
    });

    run_test("reldb_get_bit_lsb", [] {
        auto db = make_small_db();
        // record 1, attr 0, val=1 → bit1(k=1)=1, bit2(k=2)=0
        ASSERT_EQ(db.get_bit(1, 0, 1), 1);
        ASSERT_EQ(db.get_bit(1, 0, 2), 0);
    });

    run_test("reldb_get_bit_val2", [] {
        auto db = make_small_db();
        // record 2, attr 0, val=2=0b10 → bit0=0, bit1=1
        ASSERT_EQ(db.get_bit(2, 0, 1), 0);
        ASSERT_EQ(db.get_bit(2, 0, 2), 1);
    });

    run_test("reldb_set_bit_roundtrip", [] {
        auto db = make_small_db();
        db.set_bit(0, 0, 1, 1);
        ASSERT_EQ(db.records[0].attributes[0], 1);
        ASSERT_EQ(db.get_bit(0, 0, 1), 1);
        db.set_bit(0, 0, 1, 0);
        ASSERT_EQ(db.get_bit(0, 0, 1), 0);
    });

    run_test("reldb_density_zero_identical", [] {
        auto db = make_small_db();
        ASSERT_NEAR(db.fingerprint_density(db), 0.0, 1e-9);
    });

    run_test("reldb_density_one_change", [] {
        auto db = make_small_db(); auto copy = db;
        copy.records[0].attributes[0] += 1;
        ASSERT_NEAR(copy.fingerprint_density(db), 1.0, 1e-9);
    });

    run_test("reldb_density_multiple_changes", [] {
        auto db = make_small_db(); auto copy = db;
        copy.records[0].attributes[0] += 1;
        copy.records[1].attributes[1] += 2;
        copy.records[2].attributes[2] += 1;
        ASSERT_NEAR(copy.fingerprint_density(db), 4.0, 1e-9);
    });

    run_test("reldb_clip_to_domain", [] {
        auto db = make_small_db();
        db.records[0].attributes[0] = -1;
        db.records[1].attributes[1] = 99;
        db.clip_to_domain();
        ASSERT_EQ(db.records[0].attributes[0], 0);
        ASSERT_EQ(db.records[1].attributes[1], 4);
    });

    run_test("fp_params_delta1_eps1", [] {
        auto p = FingerprintParams::from_epsilon(1.0, 1, 10);
        ASSERT_EQ(p.K, 1);
        ASSERT_NEAR(p.p, 1.0/(std::exp(1.0)+1.0), 1e-9);
        ASSERT_TRUE(p.p > 0.0 && p.p < 0.5);
    });

    run_test("fp_params_delta4_eps2", [] {
        // K = ceil(log2(4)) + 1 = ceil(2.0) + 1 = 2 + 1 = 3
        auto p = FingerprintParams::from_epsilon(2.0, 4, 10);
        ASSERT_EQ(p.K, 3);
        ASSERT_NEAR(p.p, 1.0/(std::exp(2.0/3.0)+1.0), 1e-9);
    });

    run_test("fp_params_delta15_eps6", [] {
        auto p = FingerprintParams::from_epsilon(6.0, 15, 100);
        ASSERT_EQ(p.K, 5);
        ASSERT_NEAR(p.p, 1.0/(std::exp(6.0/5.0)+1.0), 1e-9);
    });

    run_test("fp_params_threshold_above_half", [] {
        int D = FingerprintParams::compute_detection_threshold(128, 100);
        ASSERT_GE(D, 64); ASSERT_LE(D, 128);
    });

    run_test("fp_params_invalid_epsilon_throws", [] {
        bool threw = false;
        try { FingerprintParams::from_epsilon(-1.0, 1, 10); }
        catch (const std::invalid_argument&) { threw = true; }
        ASSERT_TRUE(threw);
    });

    run_test("fp_params_invalid_sensitivity_throws", [] {
        bool threw = false;
        try { FingerprintParams::from_epsilon(1.0, 0, 10); }
        catch (const std::invalid_argument&) { threw = true; }
        ASSERT_TRUE(threw);
    });
}
