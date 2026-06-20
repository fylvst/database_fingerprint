/**
 * test_extractor.cpp — Unit tests for FingerprintExtractor (Algorithm 2)
 */
#include "test_framework.h"
#include "../src/fingerprint/fingerprint_extractor.h"
#include "../src/fingerprint/fingerprint_generator.h"
#include "../src/fingerprint/fingerprint_inserter.h"
#include "../src/fingerprint/types.h"
#include <random>
#include <vector>

static std::vector<uint8_t> okey(const std::string& s) { return {s.begin(),s.end()}; }

static RelationalDatabase make_db(size_t N=100, size_t T=4, int32_t max=4) {
    RelationalDatabase db;
    db.domains.resize(T);
    for (size_t t=0;t<T;++t) db.domains[t]={"a"+std::to_string(t),0,max,true};
    for (size_t i=0;i<N;++i) {
        Record r; r.primary_key=i+1; r.attributes.resize(T);
        for (size_t t=0;t<T;++t) r.attributes[t]=(int32_t)((i*7+t*3)%(max+1));
        db.records.push_back(r);
    }
    return db;
}

static RelationalDatabase random_flip(const RelationalDatabase& db, int K,
                                       double prob, uint64_t seed=42) {
    auto res=db;
    std::mt19937_64 rng(seed);
    std::uniform_real_distribution<double> d(0.0,1.0);
    for (size_t i=0;i<db.num_records();++i)
        for (size_t t=0;t<db.num_attributes();++t) {
            if (!db.domains[t].fingerprint) continue;
            int eff=std::min(K,db.domains[t].num_bits());
            for (int k=1;k<=eff;++k)
                if (d(rng)<prob) res.set_bit(i,t,k,1-res.get_bit(i,t,k));
        }
    return res;
}

static RelationalDatabase subset_keep(const RelationalDatabase& db,
                                       double keep, uint64_t seed=99) {
    auto res=db; res.records={};
    std::mt19937_64 rng(seed);
    std::uniform_real_distribution<double> d(0.0,1.0);
    for (const auto& r : db.records) if (d(rng)<keep) res.records.push_back(r);
    return res;
}

void run_extractor_tests() {

    run_test("ext_perfect_recovery", [] {
        auto k=okey("ext_test_key");
        auto p=FingerprintParams::from_epsilon(2.0,4,10);
        FingerprintGenerator gen(k); FingerprintInserter ins(p,k); FingerprintExtractor ext(p,k);
        auto db=make_db(200,4,4);
        auto [id,_]=gen.derive_and_generate(1ULL,1); auto fp=gen.generate(id);
        auto mr=ins.insert(db,fp,id);
        auto res=ext.extract(mr,db);
        ASSERT_EQ(FingerprintExtractor::count_bit_matches(res.extracted_fp,fp), 128);
        ASSERT_TRUE(res.extracted_fp==fp);
    });

    run_test("ext_processes_positions", [] {
        auto k=okey("ext_pos_key");
        auto p=FingerprintParams::from_epsilon(2.0,4,10);
        FingerprintGenerator gen(k); FingerprintInserter ins(p,k); FingerprintExtractor ext(p,k);
        auto db=make_db(100,3,4);
        auto [id,_]=gen.derive_and_generate(1ULL,1);
        auto mr=ins.insert(db,gen.generate(id),id);
        auto res=ext.extract(mr,db);
        ASSERT_GE(res.num_positions_processed, 1);
        ASSERT_EQ(res.num_records_matched, (int)db.num_records());
    });

    run_test("ext_counters_sum_to_positions", [] {
        auto k=okey("ext_cnt_key");
        auto p=FingerprintParams::from_epsilon(2.0,4,10);
        FingerprintGenerator gen(k); FingerprintInserter ins(p,k); FingerprintExtractor ext(p,k);
        auto db=make_db(50,3,4);
        auto [id,_]=gen.derive_and_generate(1ULL,1);
        auto mr=ins.insert(db,gen.generate(id),id);
        auto res=ext.extract(mr,db);
        int total=0;
        for (int l=0;l<128;++l) total+=res.c0[l]+res.c1[l];
        ASSERT_EQ(total, res.num_positions_processed);
    });

    run_test("ext_majority_vote_consistent_with_counters", [] {
        auto k=okey("ext_vote_key");
        auto p=FingerprintParams::from_epsilon(2.0,4,10);
        FingerprintGenerator gen(k); FingerprintInserter ins(p,k); FingerprintExtractor ext(p,k);
        auto db=make_db(200,4,4);
        auto [id,_]=gen.derive_and_generate(1ULL,1);
        auto mr=ins.insert(db,gen.generate(id),id);
        auto res=ext.extract(mr,db);
        for (int l=0;l<128;++l)
            ASSERT_EQ(res.extracted_fp.get_bit(l), res.c1[l]>res.c0[l] ? 1 : 0);
    });

    run_test("ext_10pct_flip_attack", [] {
        auto k=okey("ext_flip10_key");
        auto p=FingerprintParams::from_epsilon(2.0,4,10);
        FingerprintGenerator gen(k); FingerprintInserter ins(p,k); FingerprintExtractor ext(p,k);
        auto db=make_db(500,4,4);
        auto [id,_]=gen.derive_and_generate(1ULL,1); auto fp=gen.generate(id);
        auto mr=ins.insert(db,fp,id);
        auto attacked=random_flip(mr,p.K,0.10);
        auto res=ext.extract(attacked,db);
        ASSERT_GE(FingerprintExtractor::count_bit_matches(res.extracted_fp,fp), 64);
    });

    run_test("ext_subset_70pct_kept", [] {
        auto k=okey("ext_sub70_key");
        auto p=FingerprintParams::from_epsilon(2.0,4,10);
        FingerprintGenerator gen(k); FingerprintInserter ins(p,k); FingerprintExtractor ext(p,k);
        auto db=make_db(500,4,4);
        auto [id,_]=gen.derive_and_generate(1ULL,1); auto fp=gen.generate(id);
        auto mr=ins.insert(db,fp,id);
        auto leaked=subset_keep(mr,0.70);
        auto res=ext.extract(leaked,db);
        ASSERT_GE(FingerprintExtractor::count_bit_matches(res.extracted_fp,fp), 64);
    });

    run_test("ext_identify_correct_traitor", [] {
        auto k=okey("ext_traitor_key");
        auto p=FingerprintParams::from_epsilon(2.0,4,100);
        FingerprintGenerator gen(k); FingerprintInserter ins(p,k); FingerprintExtractor ext(p,k);
        auto db=make_db(300,4,4);
        std::vector<Fingerprint> fp_list; std::vector<std::string> id_list;
        for (int j=1;j<=5;++j) {
            auto [id,_]=gen.derive_and_generate((uint64_t)j,1);
            id_list.push_back(id); fp_list.push_back(gen.generate(id));
        }
        int traitor=2;
        auto mr=ins.insert(db,fp_list[traitor],id_list[traitor]);
        auto res=ext.extract(mr,db);
        auto [accused,matches]=FingerprintExtractor::identify_traitor(res.extracted_fp,fp_list,p.D);
        ASSERT_EQ(accused, traitor);
        ASSERT_GE(matches, 100);
    });

    run_test("ext_no_accusation_below_threshold", [] {
        Fingerprint rand_fp{};
        std::mt19937 rng(12345);
        for (int i=0;i<16;++i) rand_fp.data[i]=(uint8_t)(rng()&0xFF);
        FingerprintGenerator gen(okey("no_accuse_key"));
        std::vector<Fingerprint> sps;
        for (int j=1;j<=3;++j) {
            auto [id,_]=gen.derive_and_generate((uint64_t)j,1);
            sps.push_back(gen.generate(id));
        }
        auto [accused,_]=FingerprintExtractor::identify_traitor(rand_fp,sps,120);
        ASSERT_EQ(accused, -1);
    });
}
