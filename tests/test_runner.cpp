/**
 * test_runner.cpp
 *
 * Main test runner: owns g_results and main().
 * Calls all test suite functions defined in other translation units.
 */

#include "test_framework.h"

#include <cstdio>

// Global result storage (declared extern in test_framework.h)
std::vector<TestResult> g_results;

// Forward declarations of test suites
void run_crypto_tests();
void run_types_tests();
void run_generator_tests();
void run_inserter_tests();
void run_extractor_tests();
void run_integration_tests();

int main() {
    fprintf(stdout, "=== Database Fingerprinting Unit Tests ===\n");
    fprintf(stdout, "Paper: Ji et al., NDSS 2023\n\n");

    fprintf(stdout, "--- [1] Crypto Layer (HMAC, PRNG, seed) ---\n");
    run_crypto_tests();

    fprintf(stdout, "\n--- [2] Core Types (Fingerprint, RelationalDatabase, FingerprintParams) ---\n");
    run_types_tests();

    fprintf(stdout, "\n--- [3] FingerprintGenerator (f = HMAC_Y(ID_internal)) ---\n");
    run_generator_tests();

    fprintf(stdout, "\n--- [4] FingerprintInserter (Algorithm 1) ---\n");
    run_inserter_tests();

    fprintf(stdout, "\n--- [5] FingerprintExtractor (Algorithm 2 + majority voting) ---\n");
    run_extractor_tests();

    fprintf(stdout, "\n--- [6] Integration (end-to-end pipeline) ---\n");
    run_integration_tests();

    // Summary
    int passed = 0, failed = 0;
    for (const auto& r : g_results) {
        if (r.passed) ++passed; else ++failed;
    }

    fprintf(stdout, "\n============================\n");
    fprintf(stdout, "Total: %d tests\n", passed + failed);
    fprintf(stdout, "Passed: %d\n", passed);
    fprintf(stdout, "Failed: %d\n", failed);
    if (failed > 0) {
        fprintf(stdout, "\nFailed tests:\n");
        for (const auto& r : g_results) {
            if (!r.passed) {
                fprintf(stdout, "  FAIL: %s\n       %s\n",
                        r.name.c_str(), r.failure_msg.c_str());
            }
        }
    }
    fprintf(stdout, "============================\n");

    return failed == 0 ? 0 : 1;
}
