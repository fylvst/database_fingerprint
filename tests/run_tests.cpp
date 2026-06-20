/**
 * run_tests.cpp
 *
 * Unified test runner that includes all test suites.
 * Compile with the Makefile: make test
 */

// The test framework (run_test, ASSERT_*, print_summary, main) lives in test_main.cpp.
// Each test_*.cpp defines its own run_*_tests() function.
// We include everything here to produce a single binary.

// Framework + main
#include "test_main.cpp"

// Individual test suites (included, not linked, to share the run_test() function)
// We must NOT re-include test_main.cpp from these files — they include it only for
// the ASSERT macros, but since it's already included above, we use a guard.

// Forward-declare test suite entry points (defined in separate .cpp files that
// include test_main.cpp only for macros — see Makefile compile strategy below)

// Actually, the simplest approach for a header-only test framework:
// Each test file is compiled separately and linked together.
// test_main.cpp defines main() + run_test() in a single TU.
// Other test files get run_test() via the linker.

// This file IS test_main.cpp — it just re-exposes everything.
// The Makefile compiles all test_*.cpp files and links them together.
