/**
 * test_integration.cpp — End-to-end integration tests
 */
#include "test_framework.h"
#include "../src/fingerprint/fingerprint_extractor.h"
#include "../src/fingerprint/fingerprint_generator.h"
#include "../src/fingerprint/fingerprint_inserter.h"
#include "../src/fingerprint/types.h"
#include <cmath>
#include <random>
#include <vector>

static std::vector<uint8_t> K(const std::string& s) { return {s.begin(),s.end()}; }

static RelationalDatabase make_census_like(size_t N=200) {
    RelationalDatabase db;
    db.domains.resize(5);
    for (auto& d : db.domains) { d.min_val=0; d.max_val=15; d.fingerprint=true; d.name="col"; }
    std::mt19937 rng(42);
    for (size_t i=0;i<N;++i) {
        Record r; r.primary_key=i+1; r.attributes.resize(5);
        for (auto& a : r.attributes) a=(int32_t)(rng()%16);
        db.records.push_back(r);
    }
    return db;
}

void run_integration_tests() {

    run_test("int_full_pipeline_no_attack", [] {
        auto k=K("integration_key");
        auto p=FingerprintParams::from_epsilon(2.0,4,50);
        FingerprintGenerator gen(k); FingerprintInserter ins(p,k); FingerprintExtractor ext(p,k);
        auto db=make_census_like(300);
        const int C=3;
        std::vector<Fingerprint> fps; std::vector<std::string> ids;
        std::vector<RelationalDatabase> copies;
        for (int j=1;j<=C;++j) {
            auto [id,_]=gen.derive_and_generate((uint64_t)j,1);
            ids.push_back(id); fps.push_back(gen.generate(id));
            copies.push_back(ins.insert(db,fps.back(),id));
        }
        int traitor=1;
        auto res=ext.extract(copies[traitor],db);
        auto [accused,m]=FingerprintExtractor::identify_traitor(res.extracted_fp,fps,p.D);
        ASSERT_EQ(accused, traitor);
        ASSERT_GE(m, 100);
    });

    run_test("int_unique_copies_per_sp", [] {
        auto k=K("unique_copy_key");
        auto p=FingerprintParams::from_epsilon(2.0,4,10);
        FingerprintGenerator gen(k); FingerprintInserter ins(p,k);
        auto db=make_census_like(100);
        const int C=5;
        std::vector<RelationalDatabase> copies;
        for (int j=1;j<=C;++j) {
            auto [id,_]=gen.derive_and_generate((uint64_t)j,1);
            copies.push_back(ins.insert(db,gen.generate(id),id));
        }
        for (int a=0;a<C;++a) for (int b=a+1;b<C;++b) {
            int diff=0;
            for (size_t i=0;i<db.num_records();++i)
                for (size_t t=0;t<db.num_attributes();++t)
                    if (copies[a].records[i].attributes[t]!=copies[b].records[i].attributes[t]) ++diff;
            ASSERT_GE(diff,1);
        }
    });

    run_test("int_theorem1_params", [] {
        struct TC { double eps; int32_t d; int K; };
        for (auto& tc : std::vector<TC>{{1.0,1,1},{2.0,3,3},{2.0,4,3},{6.0,15,5}}) {
            auto p=FingerprintParams::from_epsilon(tc.eps,tc.d,10);
            ASSERT_EQ(p.K, tc.K);
            ASSERT_NEAR(p.p, 1.0/(std::exp(tc.eps/p.K)+1.0), 1e-10);
            ASSERT_TRUE(p.p>0.0 && p.p<0.5);
        }
    });

    run_test("int_reproducible_on_rerun", [] {
        auto k=K("repro_key");
        auto p=FingerprintParams::from_epsilon(2.0,4,10);
        FingerprintGenerator gen(k); FingerprintInserter ins(p,k);
        auto db=make_census_like(50);
        auto [id,_]=gen.derive_and_generate(42ULL,1); auto fp=gen.generate(id);
        auto r1=ins.insert(db,fp,id); auto r2=ins.insert(db,fp,id);
        for (size_t i=0;i<db.num_records();++i)
            for (size_t t=0;t<db.num_attributes();++t)
                ASSERT_EQ(r1.records[i].attributes[t], r2.records[i].attributes[t]);
    });

    run_test("int_no_false_accusation_10sp", [] {
        auto k=K("no_false_key");
        auto p=FingerprintParams::from_epsilon(2.0,4,100);
        FingerprintGenerator gen(k); FingerprintInserter ins(p,k); FingerprintExtractor ext(p,k);
        auto db=make_census_like(400);
        const int C=10; int traitor=4;
        std::vector<Fingerprint> fps; std::vector<std::string> ids;
        for (int j=1;j<=C;++j) {
            auto [id,_]=gen.derive_and_generate((uint64_t)j,1);
            ids.push_back(id); fps.push_back(gen.generate(id));
        }
        auto mr=ins.insert(db,fps[traitor],ids[traitor]);
        auto res=ext.extract(mr,db);
        auto [accused,tm]=FingerprintExtractor::identify_traitor(res.extracted_fp,fps,p.D);
        ASSERT_EQ(accused, traitor);
        for (int j=0;j<C;++j) {
            if (j==traitor) continue;
            int im=FingerprintExtractor::count_bit_matches(res.extracted_fp,fps[j]);
            ASSERT_GE(tm,im);
        }
    });
}
