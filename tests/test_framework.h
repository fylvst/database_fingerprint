/**
 * test_framework.h
 *
 * Minimal test framework shared by all test files.
 * Uses a global test registry pattern.
 */
#pragma once

#include <cmath>
#include <cstdio>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

// ============================================================================
// Test result storage (defined in test_runner.cpp)
// ============================================================================

struct TestResult {
    std::string name;
    bool        passed;
    std::string failure_msg;
};

// Global registry — defined in test_runner.cpp, declared here
extern std::vector<TestResult> g_results;

// ============================================================================
// run_test — executes a named test function and records result
// ============================================================================

inline void run_test(const std::string& name, std::function<void()> fn) {
    fprintf(stdout, "  [ RUN ] %s\n", name.c_str());
    fflush(stdout);
    try {
        fn();
        fprintf(stdout, "  [  OK ] %s\n", name.c_str());
        fflush(stdout);
        g_results.push_back({name, true, ""});
    } catch (const std::exception& e) {
        fprintf(stderr, "  [FAIL ] %s: %s\n", name.c_str(), e.what());
        fflush(stderr);
        g_results.push_back({name, false, e.what()});
    } catch (...) {
        fprintf(stderr, "  [FAIL ] %s: unknown exception\n", name.c_str());
        fflush(stderr);
        g_results.push_back({name, false, "unknown exception"});
    }
}

// ============================================================================
// Assertion macros
// ============================================================================

#define ASSERT_TRUE(cond) do { \
    if (!(cond)) { \
        char _buf[256]; \
        snprintf(_buf, sizeof(_buf), "[%s:%d] ASSERT_TRUE(%s) failed", \
                 __FILE__, __LINE__, #cond); \
        throw std::runtime_error(_buf); \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (!(_a == _b)) { \
        char _buf[512]; \
        snprintf(_buf, sizeof(_buf), "[%s:%d] ASSERT_EQ(%s, %s) failed: %lld != %lld", \
                 __FILE__, __LINE__, #a, #b, (long long)_a, (long long)_b); \
        throw std::runtime_error(_buf); \
    } \
} while(0)

#define ASSERT_NE(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a == _b) { \
        char _buf[512]; \
        snprintf(_buf, sizeof(_buf), "[%s:%d] ASSERT_NE(%s, %s) failed: both = %lld", \
                 __FILE__, __LINE__, #a, #b, (long long)_a); \
        throw std::runtime_error(_buf); \
    } \
} while(0)

#define ASSERT_GE(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (!(_a >= _b)) { \
        char _buf[512]; \
        snprintf(_buf, sizeof(_buf), "[%s:%d] ASSERT_GE(%s >= %s) failed: %lld < %lld", \
                 __FILE__, __LINE__, #a, #b, (long long)_a, (long long)_b); \
        throw std::runtime_error(_buf); \
    } \
} while(0)

#define ASSERT_LE(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (!(_a <= _b)) { \
        char _buf[512]; \
        snprintf(_buf, sizeof(_buf), "[%s:%d] ASSERT_LE(%s <= %s) failed: %lld > %lld", \
                 __FILE__, __LINE__, #a, #b, (long long)_a, (long long)_b); \
        throw std::runtime_error(_buf); \
    } \
} while(0)

#define ASSERT_NEAR(a, b, tol) do { \
    double _a = (double)(a), _b = (double)(b), _t = (double)(tol); \
    double _diff = (_a > _b) ? (_a - _b) : (_b - _a); \
    if (_diff > _t) { \
        char _buf[512]; \
        snprintf(_buf, sizeof(_buf), \
                 "[%s:%d] ASSERT_NEAR(%s, %s, %g) failed: |%.9f - %.9f| = %.9f > %g", \
                 __FILE__, __LINE__, #a, #b, _t, _a, _b, _diff, _t); \
        throw std::runtime_error(_buf); \
    } \
} while(0)
