CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -Iinclude
LDFLAGS = -shared
LDLIBS = -lmosquitto -lcyaml

# Test-specific libraries (CUnit + standard project libs)
TEST_LDLIBS = $(LDLIBS) -lcunit

# Define the build directories
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj
TEST_BUILD_DIR = $(BUILD_DIR)/test

# The final plugin target
TARGET = $(BUILD_DIR)/waf.so

# Autodiscover source files
SRCS = $(shell find src -type f -name '*.c')
OBJS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRCS))

all: $(TARGET)

# Rule to link the final plugin target (.so)
$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# Rule to compile source files into object files (.o)
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# --- Test Targets ---

# Autodiscover test files (files starting with 'test_')
TEST_SRCS = $(shell find test -type f -name 'test_*.c')
TEST_BINS = $(patsubst test/%.c,$(TEST_BUILD_DIR)/%,$(TEST_SRCS))

# Autodiscover mock files (files ending in '_mock.c')
MOCK_SRCS = $(shell find test -type f -name '*_mock.c')
MOCK_OBJS = $(patsubst test/%.c,$(OBJ_DIR)/test/%.o,$(MOCK_SRCS))

# Rule to compile mock objects
$(OBJ_DIR)/test/%.o: test/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST_BINS)
	@echo "====================="
	@echo "   RUNNING TESTS     "
	@echo "====================="
	@for test_bin in $(TEST_BINS); do \
		echo "\nExecuting $$test_bin..."; \
		./$$test_bin || exit 1; \
	done

# Rule to compile test executables (now linking MOCK_OBJS as well)
$(TEST_BUILD_DIR)/%: test/%.c $(OBJS) $(MOCK_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< $(OBJS) $(MOCK_OBJS) -o $@ $(TEST_LDLIBS)

docs:
	@echo "Generating Doxygen documentation..."
	doxygen Doxyfile

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean test