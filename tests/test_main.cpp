/**
 * test_main.cpp
 *
 * Minimal test runner — no external testing framework required.
 * Uses simple assertion macros with descriptive failure output.
 *
 * Run: ./test_fingerprint
 */

#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <vector>

// ============================================================================
// Minimal test framework
// ============================================================================

struct TestResult {
    std::string name;
    bool        passed;
    std::string failure_msg;
};

static std::vector<TestResult> g_results;
static std::string             g_current_test;

#define TEST(name) \
    static void test_##name(); \
    static bool reg_##name = ([]{ \
        g_results.push_back({#name, true, ""}); \
        return true; \
    }(), true); \
    static void test_##name()

#define REGISTER(name) g_results.push_back({#name, true, ""})

#define ASSERT_TRUE(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "  FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #cond); \
        throw std::runtime_error("assertion failed: " #cond); \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a != _b) { \
        fprintf(stderr, "  FAIL [%s:%d]: %s == %s  (%lld != %lld)\n", \
            __FILE__, __LINE__, #a, #b, (long long)_a, (long long)_b); \
        throw std::runtime_error("assertion failed: " #a " == " #b); \
    } \
} while(0)

#define ASSERT_NE(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a == _b) { \
        fprintf(stderr, "  FAIL [%s:%d]: %s != %s  (both = %lld)\n", \
            __FILE__, __LINE__, #a, #b, (long long)_a); \
        throw std::runtime_error("assertion failed: " #a " != " #b); \
    } \
} while(0)

#define ASSERT_GE(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (!(_a >= _b)) { \
        fprintf(stderr, "  FAIL [%s:%d]: %s >= %s  (%lld < %lld)\n", \
            __FILE__, __LINE__, #a, #b, (long long)_a, (long long)_b); \
        throw std::runtime_error("assertion failed: " #a " >= " #b); \
    } \
} while(0)

#define ASSERT_LE(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (!(_a <= _b)) { \
        fprintf(stderr, "  FAIL [%s:%d]: %s <= %s  (%lld > %lld)\n", \
            __FILE__, __LINE__, #a, #b, (long long)_a, (long long)_b); \
        throw std::runtime_error("assertion failed: " #a " <= " #b); \
    } \
} while(0)

#define ASSERT_NEAR(a, b, tol) do { \
    double _a = (a), _b = (b), _t = (tol); \
    double _diff = _a > _b ? _a - _b : _b - _a; \
    if (_diff > _t) { \
        fprintf(stderr, "  FAIL [%s:%d]: |%s - %s| <= %s  (|%.6f - %.6f| = %.6f)\n", \
            __FILE__, __LINE__, #a, #b, #tol, _a, _b, _diff); \
        throw std::runtime_error("assertion failed: near"); \
    } \
} while(0)

// Run a single named test function
void run_test(const std::string& name, std::function<void()> fn) {
    fprintf(stdout, "  [ RUN ] %s\n", name.c_str());
    try {
        fn();
        fprintf(stdout, "  [  OK ] %s\n", name.c_str());
        g_results.push_back({name, true, ""});
    } catch (const std::exception& e) {
        fprintf(stderr, "  [FAIL ] %s: %s\n", name.c_str(), e.what());
        g_results.push_back({name, false, e.what()});
    }
}

// Print summary and return exit code
int print_summary() {
    int passed = 0, failed = 0;
    for (auto& r : g_results) {
        if (r.passed) ++passed; else ++failed;
    }
    fprintf(stdout, "\n============================\n");
    fprintf(stdout, "Results: %d passed, %d failed\n", passed, failed);
    if (failed > 0) {
        fprintf(stdout, "FAILED tests:\n");
        for (auto& r : g_results) {
            if (!r.passed) fprintf(stdout, "  - %s: %s\n", r.name.c_str(), r.failure_msg.c_str());
        }
    }
    fprintf(stdout, "============================\n");
    return failed == 0 ? 0 : 1;
}

// Forward declarations of test suites
void run_crypto_tests();
void run_types_tests();
void run_generator_tests();
void run_inserter_tests();
void run_extractor_tests();
void run_integration_tests();

int main() {
    fprintf(stdout, "=== Database Fingerprinting Unit Tests ===\n\n");

    fprintf(stdout, "--- Crypto Layer ---\n");
    run_crypto_tests();

    fprintf(stdout, "\n--- Core Types ---\n");
    run_types_tests();

    fprintf(stdout, "\n--- FingerprintGenerator ---\n");
    run_generator_tests();

    fprintf(stdout, "\n--- FingerprintInserter (Algorithm 1) ---\n");
    run_inserter_tests();

    fprintf(stdout, "\n--- FingerprintExtractor (Algorithm 2) ---\n");
    run_extractor_tests();

    fprintf(stdout, "\n--- Integration (Alg1 + Alg2 end-to-end) ---\n");
    run_integration_tests();

    return print_summary();
}
