/**
 * types.cpp
 *
 * Implementations of RelationalDatabase and FingerprintParams methods.
 */

#include "types.h"

#include <cmath>
#include <stdexcept>

// ============================================================================
// RelationalDatabase
// ============================================================================

int RelationalDatabase::get_bit(size_t record_idx,
                                 size_t attr_idx,
                                 int k) const {
    if (record_idx >= records.size()) throw std::out_of_range("get_bit: record_idx");
    if (attr_idx >= domains.size())   throw std::out_of_range("get_bit: attr_idx");
    if (k < 1) throw std::invalid_argument("get_bit: k must be >= 1");

    int32_t val = records[record_idx].attributes[attr_idx];
    // k=1 → bit 0 (LSB), k=2 → bit 1, etc.
    return (val >> (k - 1)) & 1;
}

void RelationalDatabase::set_bit(size_t record_idx,
                                  size_t attr_idx,
                                  int k,
                                  int bit_val) {
    if (record_idx >= records.size()) throw std::out_of_range("set_bit: record_idx");
    if (attr_idx >= domains.size())   throw std::out_of_range("set_bit: attr_idx");
    if (k < 1) throw std::invalid_argument("set_bit: k must be >= 1");

    int32_t& val = records[record_idx].attributes[attr_idx];
    int shift = k - 1;
    if (bit_val) {
        val |= (1 << shift);
    } else {
        val &= ~(1 << shift);
    }
}

double RelationalDatabase::fingerprint_density(
    const RelationalDatabase& original) const {

    if (records.size() != original.records.size()) {
        throw std::invalid_argument("fingerprint_density: size mismatch");
    }
    if (domains.size() != original.domains.size()) {
        throw std::invalid_argument("fingerprint_density: attribute count mismatch");
    }

    double total = 0.0;
    for (size_t i = 0; i < records.size(); ++i) {
        for (size_t t = 0; t < domains.size(); ++t) {
            double diff = std::abs(static_cast<double>(records[i].attributes[t]) -
                                   static_cast<double>(original.records[i].attributes[t]));
            total += diff;
        }
    }
    return total;
}

void RelationalDatabase::clip_to_domain() {
    for (auto& rec : records) {
        for (size_t t = 0; t < domains.size(); ++t) {
            int32_t& val = rec.attributes[t];
            if (val < domains[t].min_val) val = domains[t].min_val;
            if (val > domains[t].max_val) val = domains[t].max_val;
        }
    }
}

// ============================================================================
// FingerprintParams
// ============================================================================

FingerprintParams FingerprintParams::from_epsilon(double epsilon,
                                                   int32_t sensitivity,
                                                   int C) {
    if (epsilon <= 0.0) throw std::invalid_argument("epsilon must be > 0");
    if (sensitivity < 1) throw std::invalid_argument("sensitivity must be >= 1");
    if (C < 1) throw std::invalid_argument("C must be >= 1");

    FingerprintParams p{};
    p.epsilon     = epsilon;
    p.sensitivity = sensitivity;
    p.L           = Fingerprint::LENGTH_BITS;  // 128
    p.C           = C;

    // Theorem 1: K = ceil(log2(Δ)) + 1
    p.K = static_cast<int>(std::ceil(std::log2(static_cast<double>(sensitivity)))) + 1;
    if (p.K < 1) p.K = 1;

    // Theorem 1: p = 1 / (e^(ε/K) + 1)
    p.p = 1.0 / (std::exp(epsilon / static_cast<double>(p.K)) + 1.0);

    // Sanity check: p must be < 0.5 (required by proof, p < 1/2)
    if (p.p >= 0.5) {
        throw std::runtime_error("p >= 0.5: epsilon is too small for given sensitivity");
    }

    // Compute detection threshold D
    p.D = compute_detection_threshold(p.L, C);

    return p;
}

int FingerprintParams::compute_detection_threshold(int L, int C) {
    // Paper Appendix C:
    // Find minimum D such that P(random L-bit string matches target in >= D positions) < 1/C
    // i.e., sum_{d=D}^{L} C(L,d) * (1/2)^L >= 1/C  (probability of false accusation)
    // We want this probability to be small enough that we can uniquely identify the traitor.
    //
    // ASSUMPTION: We set D as the minimum integer such that the binomial tail
    //   sum_{d=D}^{L} C(L,d) * 0.5^L  <  1/C
    // is satisfied. This follows the paper's Appendix C criterion.

    // Use log-space computation to avoid overflow
    // Compute log of each C(L,d) * 0.5^L using Stirling / log-gamma
    auto log_binom_prob = [&](int d) -> double {
        // log( C(L,d) * 0.5^L )
        double log_comb = 0.0;
        for (int i = 0; i < d; ++i) {
            log_comb += std::log(static_cast<double>(L - i)) - std::log(static_cast<double>(i + 1));
        }
        return log_comb - static_cast<double>(L) * std::log(2.0);
    };

    double threshold_log = std::log(1.0 / static_cast<double>(C));
    // Accumulate tail probability from L down to L/2
    // log_sum_exp trick
    std::vector<double> log_terms(L + 1);
    for (int d = 0; d <= L; ++d) {
        log_terms[d] = log_binom_prob(d);
    }

    // Find D: largest D such that log(sum_{d=D}^{L} ...) >= threshold_log
    for (int D = L / 2; D <= L; ++D) {
        // Compute log(sum_{d=D}^{L} p(d)) using log-sum-exp
        double max_log = log_terms[D];
        for (int d = D + 1; d <= L; ++d) max_log = std::max(max_log, log_terms[d]);

        double sum = 0.0;
        for (int d = D; d <= L; ++d) sum += std::exp(log_terms[d] - max_log);
        double log_prob = max_log + std::log(sum);

        if (log_prob < threshold_log) {
            // D is too high — use D-1 as threshold
            return (D > L / 2) ? D : D + 1;
        }
    }
    return L / 2 + 1;  // fallback: slightly above half
}
