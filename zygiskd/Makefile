ROOT_DIR := ..
include ../common.mk

# INFO: common.mk carries the rule that builds the Rust archive, and a rule is
#       what decides the default goal: make takes the first target of the first
#       rule it read, and an include is read before the rest of this file. So
#       without this line `make -C zygiskd` would build libvexcore.a and stop,
#       and the packaging step would then look for the daemon it never got.
#
#       The goal is the one this Makefile has always defaulted to.
.DEFAULT_GOAL := all
OBJ_ROOT = $(BUILD_DIR)/obj/$(BUILD_TYPE)/zygiskd
OBJ_DIR = $(OBJ_ROOT)/$(ARCH)

ZKSU_VERSION ?= $(VER_NAME)

ifeq ($(BUILD_TYPE),release)
	TYPE_CFLAGS = -O3 -flto -DNDEBUG
	TYPE_LDFLAGS = -Wl,--strip-all -flto
else
	TYPE_CFLAGS = -g -O0 -DDEBUG
	TYPE_LDFLAGS =
endif

# INFO: One function per section, and one section per datum, so the linker can
#       drop what nothing reaches. The daemon has a 56 KiB budget and most of
#       its source is reachable from the action table, but the root-impl and
#       utility files carry helpers for both flavours; --gc-sections keeps the
#       other flavour's code out of each binary.
TYPE_CFLAGS += -ffunction-sections -fdata-sections
TYPE_LDFLAGS += -Wl,--gc-sections

ZYGISKD_CFLAGS = -D_GNU_SOURCE -std=c99 -Wpedantic -Wall -Wextra -Werror  \
			 	 -Wformat -Wuninitialized -Wshadow -Wno-zero-length-array \
			 	 -Wno-unknown-warning-option -Wconversion                 \
			 	 $(ROOT_IMPL_DEF)                                         \
			 	 '-DZKSU_VERSION="$(ZKSU_VERSION)"'

ROOT_IMPL_SRC = $(if $(filter apatch,$(ROOT_IMPL)),src/root_impl/apatch.c,src/root_impl/kernelsu.c)

SRCS = src/root_impl/common.c $(ROOT_IMPL_SRC) \
	   src/companion.c src/main.c src/utils.c src/zygiskd.c

OBJS = $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SRCS))
BIN = $(OBJ_DIR)/zygiskd

INCLUDES = -Isrc -Isrc/root_impl -I../loader/src/include

.PHONY: all arch clean

all: arch
	@mkdir -p $(OBJ_ROOT)
	@touch $(OBJ_ROOT)/.done

arch: $(BIN)

clean:
	rm -rf $(BUILD_DIR)/obj/$(BUILD_TYPE)/zygiskd

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(ZYGISKD_CFLAGS) $(TYPE_CFLAGS) $(INCLUDES) -c $< -o $@

$(BIN): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(TYPE_LDFLAGS) $(OBJS) -llog -o $@
