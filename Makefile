# Makefile for database_fingerprint (NDSS 2023 Privacy-Preserving DB Fingerprinting)
#
# Requirements: OpenSSL 3.x (via Homebrew on macOS)
#   brew install openssl@3
#
# Usage:
#   make           — build the main library and test binary
#   make test      — build and run all unit tests
#   make clean     — remove all build artifacts

# ============================================================================
# Compiler and flags
# ============================================================================

CXX      := c++
STD      := -std=c++17
WARNINGS := -Wall -Wextra -Wpedantic -Wshadow -Wno-unused-parameter
OPTIM    := -O2 -g

# OpenSSL: try Homebrew locations for macOS (arm64 and x86_64)
OPENSSL_PREFIX ?= /opt/homebrew/opt/openssl@3

CXXFLAGS := $(STD) $(WARNINGS) $(OPTIM) \
             -I$(OPENSSL_PREFIX)/include

LDFLAGS  := -L$(OPENSSL_PREFIX)/lib \
             -lssl -lcrypto

# ============================================================================
# Source files
# ============================================================================

SRC_DIR   := src
TEST_DIR  := tests

# Library sources (all .cpp under src/)
LIB_SRCS := \
    $(SRC_DIR)/crypto/crypto_utils.cpp         \
    $(SRC_DIR)/fingerprint/types.cpp           \
    $(SRC_DIR)/fingerprint/fingerprint_generator.cpp  \
    $(SRC_DIR)/fingerprint/fingerprint_inserter.cpp   \
    $(SRC_DIR)/fingerprint/fingerprint_extractor.cpp

# Test sources
TEST_SRCS := \
    $(TEST_DIR)/test_runner.cpp          \
    $(TEST_DIR)/test_crypto.cpp          \
    $(TEST_DIR)/test_types.cpp           \
    $(TEST_DIR)/test_generator.cpp       \
    $(TEST_DIR)/test_inserter.cpp        \
    $(TEST_DIR)/test_extractor.cpp       \
    $(TEST_DIR)/test_integration.cpp

# ============================================================================
# Build directories and object files
# ============================================================================

BUILD_DIR := build
LIB_OBJS  := $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(LIB_SRCS))
TEST_OBJS := $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(TEST_SRCS))

TEST_BIN  := $(BUILD_DIR)/test_fingerprint

# ============================================================================
# Default target: build test binary
# ============================================================================

.PHONY: all
all: $(TEST_BIN)

# ============================================================================
# Run tests
# ============================================================================

.PHONY: test
test: $(TEST_BIN)
	@echo ""
	@echo "Running tests..."
	@echo "================"
	@$(TEST_BIN)

# ============================================================================
# Link test binary
# ============================================================================

$(TEST_BIN): $(LIB_OBJS) $(TEST_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(STD) $^ $(LDFLAGS) -o $@
	@echo "Linked: $@"

# ============================================================================
# Compile source files
# ============================================================================

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# ============================================================================
# Dependency tracking (auto-generated .d files)
# ============================================================================

DEPS := $(LIB_OBJS:.o=.d) $(TEST_OBJS:.o=.d)

$(BUILD_DIR)/%.d: %.cpp
	@mkdir -p $(dir $@)
	@$(CXX) $(CXXFLAGS) -MM -MT '$(BUILD_DIR)/$*.o' $< > $@

-include $(DEPS)

# ============================================================================
# Clean
# ============================================================================

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	@echo "Cleaned."

# ============================================================================
# Info: print detected configuration
# ============================================================================

.PHONY: info
info:
	@echo "CXX         = $(CXX)"
	@echo "CXXFLAGS    = $(CXXFLAGS)"
	@echo "LDFLAGS     = $(LDFLAGS)"
	@echo "LIB_SRCS    = $(LIB_SRCS)"
	@echo "TEST_SRCS   = $(TEST_SRCS)"
	@echo "TEST_BIN    = $(TEST_BIN)"
