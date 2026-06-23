CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -Iinclude
LDFLAGS = -shared
LDLIBS = -lmosquitto -lcyaml

# Define the build directories
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj

# The final target goes directly into the build/ directory
TARGET = $(BUILD_DIR)/waf.so

# Autodiscover all .c files inside the src/ directory and its subdirectories
SRCS = $(shell find src -type f -name '*.c')

# Map the discovered .c files to .o files inside the build/obj/ directory
OBJS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRCS))

all: $(TARGET)

# Rule to link the final target (.so)
$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# Rule to compile source files into object files (.o)
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean