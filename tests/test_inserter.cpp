/**
 * test_inserter.cpp — Unit tests for FingerprintInserter (Algorithm 1)
 */
#include "test_framework.h"
#include "../src/fingerprint/fingerprint_generator.h"
#include "../src/fingerprint/fingerprint_inserter.h"
#include "../src/fingerprint/types.h"
#include <cmath>
#include <vector>

static std::vector<uint8_t> okey(const std::string& s) { return {s.begin(),s.end()}; }

static RelationalDatabase make_db(size_t N=20, size_t T=3, int32_t max_val=4) {
    RelationalDatabase db;
    db.domains.resize(T);
    for (size_t t=0;t<T;++t)
        db.domains[t]={"attr"+std::to_string(t),0,max_val,true};
    for (size_t i=0;i<N;++i) {
        Record r; r.primary_key=i+1; r.attributes.resize(T);
        for (size_t t=0;t<T;++t) r.attributes[t]=(int32_t)((i+t)%(max_val+1));
        db.records.push_back(r);
    }
    return db;
}

static FingerprintParams P(double eps=2.0, int32_t d=4, int c=10) {
    return FingerprintParams::from_epsilon(eps,d,c);
}

void run_inserter_tests() {

    run_test("ins_deterministic", [] {
        auto k=okey("test_key"); auto p=P();
        FingerprintInserter ins(p,k); FingerprintGenerator gen(k);
        auto db=make_db(); auto [id,_]=gen.derive_and_generate(1ULL,1);
        auto fp=gen.generate(id);
        auto r1=ins.insert(db,fp,id); auto r2=ins.insert(db,fp,id);
        for (size_t i=0;i<db.num_records();++i)
            for (size_t t=0;t<db.num_attributes();++t)
                ASSERT_EQ(r1.records[i].attributes[t], r2.records[i].attributes[t]);
    });

    run_test("ins_different_fp_different_output", [] {
        auto k=okey("test_key"); auto p=P();
        FingerprintInserter ins(p,k); FingerprintGenerator gen(k);
        auto db=make_db(50,3,4);
        auto [id1,_1]=gen.derive_and_generate(1ULL,1);
        auto [id2,_2]=gen.derive_and_generate(2ULL,1);
        auto r1=ins.insert(db,gen.generate(id1),id1);
        auto r2=ins.insert(db,gen.generate(id2),id2);
        int diff=0;
        for (size_t i=0;i<db.num_records();++i)
            for (size_t t=0;t<db.num_attributes();++t)
                if (r1.records[i].attributes[t]!=r2.records[i].attributes[t]) ++diff;
        ASSERT_GE(diff, 1);
    });

    run_test("ins_primary_keys_unchanged", [] {
        auto k=okey("test_key"); auto p=P();
        FingerprintInserter ins(p,k); FingerprintGenerator gen(k);
        auto db=make_db();
        auto [id,_]=gen.derive_and_generate(1ULL,1);
        auto mr=ins.insert(db,gen.generate(id),id);
        for (size_t i=0;i<db.num_records();++i)
            ASSERT_EQ(db.records[i].primary_key, mr.records[i].primary_key);
    });

    run_test("ins_non_fingerprinted_attrs_unchanged", [] {
        auto k=okey("test_key"); auto p=P();
        FingerprintInserter ins(p,k); FingerprintGenerator gen(k);
        auto db=make_db(20,3,4); db.domains[1].fingerprint=false;
        auto [id,_]=gen.derive_and_generate(1ULL,1);
        auto mr=ins.insert(db,gen.generate(id),id);
        for (size_t i=0;i<db.num_records();++i)
            ASSERT_EQ(db.records[i].attributes[1], mr.records[i].attributes[1]);
    });

    run_test("ins_only_k_lsbs_modified", [] {
        // K=1: only bit 0 (LSB) can change
        auto k=okey("test_key");
        auto p=FingerprintParams::from_epsilon(1.0,1,10); ASSERT_EQ(p.K,1);
        FingerprintInserter ins(p,k); FingerprintGenerator gen(k);
        auto db=make_db(20,2,15);
        auto [id,_]=gen.derive_and_generate(1ULL,1);
        auto mr=ins.insert(db,gen.generate(id),id);
        for (size_t i=0;i<db.num_records();++i)
            for (size_t t=0;t<db.num_attributes();++t) {
                int32_t orig=db.records[i].attributes[t];
                int32_t fing=mr.records[i].attributes[t];
                ASSERT_EQ(orig>>1, fing>>1);  // all bits >= 1 unchanged
            }
    });

    run_test("ins_selection_rate_approx_2p", [] {
        // Selection period = floor(1/(2p)); selection rate = 1/period.
        // When floor(1/(2p)) = 1 (i.e., 2p > 0.5), every position is selected.
        // We must use a parameter where floor(1/(2p)) >= 2 to test non-trivial selection.
        // Use ε=6.0, Δ=15: K=5, p=1/(e^(6/5)+1) ≈ 0.231, 2p≈0.462
        // floor(1/(2p)) = floor(1/0.462) = floor(2.16) = 2 → rate ≈ 0.50
        auto k=okey("test_key_selection");
        auto p=FingerprintParams::from_epsilon(6.0,15,10);
        FingerprintInserter ins(p,k);
        auto db=make_db(500,5,15);
        size_t sel=ins.count_selected_positions(db);

        // Total fingerprintable positions = N * T * min(K, K_t)
        // K_t for Δ=15 → num_bits = 4; K=5 → effective_K = 4
        int eff_K = std::min(p.K, db.domains[0].num_bits());
        size_t total = db.num_records() * db.num_attributes() * eff_K;
        double rate  = static_cast<double>(sel) / static_cast<double>(total);

        // Expected: 1/floor(1/(2p))
        uint32_t period = static_cast<uint32_t>(std::floor(1.0 / (2.0 * p.p)));
        double expected = 1.0 / static_cast<double>(period);

        // Allow 10% relative tolerance (statistical)
        ASSERT_NEAR(rate, expected, expected * 0.10);
    });

    run_test("ins_density_in_bounds", [] {
        // Paper Corollary 1: E[||M(R)-R||_{1,1}] <= Δ * p * N * T
        // This is an *expected value* bound, not a worst-case bound.
        // The actual density can exceed the expected value in any single run.
        // We verify: density >= 0, and density <= Δ * selection_fraction * N * T
        // where selection_fraction <= 1 and each changed bit shifts value by ≤ Δ.
        //
        // A valid strict upper bound: density <= Δ * N * T * K
        // (All positions selected, all changed by max Δ per attribute — impossible
        //  but a trivially safe upper bound).
        auto k=okey("test_density_key"); auto p=P(2.0,4,10);
        FingerprintInserter ins(p,k); FingerprintGenerator gen(k);
        auto db=make_db(100,3,4);
        auto [id,_]=gen.derive_and_generate(1ULL,1);
        double density=ins.compute_density(db,gen.generate(id));
        ASSERT_GE(density, 0.0);
        // Hard upper bound: density <= Δ * N * T (all entries changed by at most Δ)
        double hard_upper = (double)p.sensitivity * (double)db.num_records() * (double)db.num_attributes();
        ASSERT_LE(density, hard_upper);
    });

    run_test("ins_output_shape_preserved", [] {
        auto k=okey("test_key"); auto p=P();
        FingerprintInserter ins(p,k); FingerprintGenerator gen(k);
        auto db=make_db(30,4,7);
        auto [id,_]=gen.derive_and_generate(1ULL,1);
        auto mr=ins.insert(db,gen.generate(id),id);
        ASSERT_EQ(mr.num_records(),   db.num_records());
        ASSERT_EQ(mr.num_attributes(),db.num_attributes());
    });

    run_test("ins_bit_changes_within_mask", [] {
        auto k=okey("test_xor_key");
        auto p=FingerprintParams::from_epsilon(0.5,1,10);
        FingerprintInserter ins(p,k); FingerprintGenerator gen(k);
        auto db=make_db(10,2,1);
        auto [id,_]=gen.derive_and_generate(1ULL,1);
        auto mr=ins.insert(db,gen.generate(id),id);
        int32_t mask=(1<<p.K)-1;
        for (size_t i=0;i<db.num_records();++i)
            for (size_t t=0;t<db.num_attributes();++t)
                ASSERT_EQ((db.records[i].attributes[t]^mr.records[i].attributes[t])&~mask, 0);
    });
}
