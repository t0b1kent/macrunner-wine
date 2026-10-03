# Source-only reconstruction of the retained MIT HyperBridge archive.
SRC_ROOT ?= .
BUILD_ROOT ?= ../../_build/hyperbridge
CC = /usr/bin/clang
AR = /usr/bin/ar
CFLAGS = -O2 -std=c11 -fPIC -fvisibility=hidden -arch arm64 -mmacosx-version-min=14.0 -I$(SRC_ROOT)/include -MMD -MP
SOURCES = $(sort $(wildcard $(SRC_ROOT)/src/*.c))
OBJECTS = $(patsubst $(SRC_ROOT)/src/%.c,$(BUILD_ROOT)/%.o,$(SOURCES))

.PHONY: all
all: $(BUILD_ROOT)/libhyperbridge.a

$(BUILD_ROOT)/libhyperbridge.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

$(BUILD_ROOT)/%.o: $(SRC_ROOT)/src/%.c
	@mkdir -p $(BUILD_ROOT)
	$(CC) $(CFLAGS) -c $< -o $@

-include $(OBJECTS:.o=.d)
