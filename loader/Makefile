ROOT_DIR := ..
include ../common.mk

# common.mk carries the rule that builds the Rust archive, and a rule decides the
# default goal: make takes the first target of the first rule it read, and an
# include is read before the rest of this file. Without this line `make -C
# loader` would build libvexcore.a and stop.
.DEFAULT_GOAL := all
OBJ_ROOT = $(BUILD_DIR)/obj/$(BUILD_TYPE)/loader
OBJ_DIR = $(OBJ_ROOT)/$(ARCH)

ZKSU_VERSION ?= $(VER_NAME)-$(VER_CODE)-$(COMMIT_HASH)-$(BUILD_TYPE)

ifeq ($(BUILD_TYPE),release)
	# The injected library is size-sensitive on top of being hot: -Oz plus
	# identical code folding buys back part of what the statically linked
	# engines cost, without giving up the LTO gains.
	TYPE_CFLAGS = -Oz -flto -Wno-unused -Wno-unused-parameter       \
				  -fvisibility=hidden -fvisibility-inlines-hidden -fno-unwind-tables \
				  -fno-asynchronous-unwind-tables -DNDEBUG
	TYPE_LDFLAGS = -Wl,--exclude-libs,ALL -Wl,--strip-all -flto -Wl,--icf=safe
else
	TYPE_CFLAGS = -g -O0
	TYPE_LDFLAGS =
endif

# Everything here is C: the two hook engines that needed a C++ bridge are gone,
# so the module only has to agree with its own headers.
LOADER_CFLAGS = -std=c18 -D_GNU_SOURCE -Wall -Wextra -fno-stack-protector -fomit-frame-pointer \
				-Wno-builtin-macro-redefined                                                 \
				$(ROOT_IMPL_DEF)                                                            \
				'-D__FILE__=__FILE_NAME__' -DZKSU_VERSION=\"$(ZKSU_VERSION)\"

COMMON_LDFLAGS = -Wl,--build-id=sha1 -Wl,--no-rosegment                   \
				 -Wl,--no-undefined-version -Wl,--fatal-warnings -Wl,--no-undefined \
				 -Wl,--gc-sections

COMMON_SRCS = src/common/daemon.c src/common/elf_util.c   \
			  src/common/misc.c src/common/socket_utils.c
INJECTOR_SRCS = src/injector/cpp_strings.c src/injector/entry.c \
				src/injector/hiding.c src/injector/hook.c \
				src/injector/ptrace_clear.c \
				src/injector/zn_api.c src/injector/zn_loader.c \
				src/injector/unmount.c
PTRACER_SRCS = src/ptracer/main.c src/ptracer/monitor.c src/ptracer/monitor_status.c \
			   src/ptracer/ptracer.c src/ptracer/utils.c

COMMON_OBJS = $(patsubst src/common/%.c,$(OBJ_DIR)/common/%.o,$(COMMON_SRCS))
INJECTOR_OBJS = $(patsubst src/injector/%.c,$(OBJ_DIR)/injector/%.o,$(INJECTOR_SRCS))
PTRACER_OBJS = $(patsubst src/ptracer/%.c,$(OBJ_DIR)/ptracer/%.o,$(PTRACER_SRCS))

PLTI_LIB = $(BUILD_DIR)/obj/$(BUILD_TYPE)/plti/$(ARCH)/libplti.a
CSOLOADER_LIB = $(BUILD_DIR)/obj/$(BUILD_TYPE)/csoloader/$(ARCH)/libcsoloader.a

LIBCOMMON = $(OBJ_DIR)/libcommon.a

LIBZYGISK = $(OBJ_DIR)/libzygisk.so
LIBPTRACE = $(OBJ_DIR)/libzygisk_ptrace.so
LIBZYGISK_STRIPPED = $(OBJ_DIR)/stripped/libzygisk.so
LIBPTRACE_STRIPPED = $(OBJ_DIR)/stripped/libzygisk_ptrace.so

PLTI_DIR = src/external/plti
CSOLOADER_DIR = src/external/csoloader
LZMA_DIR = src/external/lzma

COMMON_INCLUDES = -Isrc/include -I$(LZMA_DIR)
INJECTOR_INCLUDES = -Isrc/include -I$(PLTI_DIR)/src -I$(CSOLOADER_DIR)/include

.PHONY: all arch clean

all: arch

arch: $(LIBZYGISK_STRIPPED) $(LIBPTRACE_STRIPPED)

clean:
	rm -rf $(BUILD_DIR)/obj/$(BUILD_TYPE)/loader
	rm -rf $(BUILD_DIR)/obj/$(BUILD_TYPE)/plti
	rm -rf $(BUILD_DIR)/obj/$(BUILD_TYPE)/csoloader
	rm -rf $(BUILD_DIR)/obj/$(BUILD_TYPE)/vexcore
	rm -rf $(BUILD_DIR)/obj/$(BUILD_TYPE)/vexcore-target

# Both engines are built by their own Makefiles in a sub-make, which this one
# cannot see into: without a prerequisite the library would be built once and
# then taken as up to date forever, and a submodule update would link a stale
# archive.
PLTI_INPUTS = $(shell find $(PLTI_DIR) -type f 2>/dev/null | sort)
CSOLOADER_INPUTS = $(shell find $(CSOLOADER_DIR) -type f 2>/dev/null | sort)

$(PLTI_LIB): $(PLTI_INPUTS)
	@mkdir -p $(dir $@)
	$(MAKE) -C $(PLTI_DIR) BUILD_TYPE=$(BUILD_TYPE) ARCH=$(ARCH) \
		NDK_PATH=$(NDK_PATH) API_LEVEL=$(API_LEVEL)              \
		out=$(BUILD_DIR)/obj/$(BUILD_TYPE)/plti/$(ARCH)

$(CSOLOADER_LIB): $(CSOLOADER_INPUTS)
	@mkdir -p $(dir $@)
	$(MAKE) -C $(CSOLOADER_DIR) BUILD_TYPE=$(BUILD_TYPE) ARCH=$(ARCH) \
		NDK_PATH=$(NDK_PATH) API_LEVEL=$(API_LEVEL)                   \
		out=$(BUILD_DIR)/obj/$(BUILD_TYPE)/csoloader/$(ARCH)

$(OBJ_DIR)/common/%.o: src/common/%.c
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(NDK_CFLAGS) $(LOADER_CFLAGS) $(TYPE_CFLAGS) \
		$(COMMON_INCLUDES) -fPIC -c $< -o $@

$(OBJ_DIR)/injector/%.o: src/injector/%.c
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(NDK_CFLAGS) $(LOADER_CFLAGS) $(TYPE_CFLAGS) \
		$(INJECTOR_INCLUDES) -Dzygisk_EXPORTS -fPIC -c $< -o $@

$(OBJ_DIR)/ptracer/%.o: src/ptracer/%.c
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(NDK_CFLAGS) $(LOADER_CFLAGS) $(TYPE_CFLAGS) \
		$(COMMON_INCLUDES) -fPIE -c $< -o $@

# xz-embedded, built the way its own build does: dynamic allocation for the
# dictionary, every integrity check accepted and its internal CRC32 instead of a
# kernel one.
LZMA_CFLAGS = -D_GNU_SOURCE -std=c11 -fno-stack-protector -fomit-frame-pointer \
	-Wno-unused -Wno-sign-compare -DNDEBUG \
	-DXZ_DEC_DYNALLOC=1 -DXZ_DEC_ANY_CHECK=1 -DXZ_INTERNAL_CRC32=1 \
	-DNOINLINE=noinline_for_stack

LZMA_SRCS = xz_dec_lzma2.c xz_dec_stream.c xz_dec_bcj.c
LZMA_OBJS = $(patsubst %.c,$(OBJ_DIR)/external/lzma/%.o,$(LZMA_SRCS))

$(LZMA_OBJS): $(OBJ_DIR)/external/lzma/%.o: $(LZMA_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(NDK_CFLAGS) $(LZMA_CFLAGS) $(COMMON_INCLUDES) -fPIC -c $< -o $@

$(LIBCOMMON): $(COMMON_OBJS) $(LZMA_OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

$(LIBZYGISK): $(INJECTOR_OBJS) $(LIBCOMMON) $(VEXCORE_LIB) $(PLTI_LIB) $(CSOLOADER_LIB)
	@mkdir -p $(dir $@)
	$(CC_ARCH) -fPIC -shared -Wl,-soname,libzygisk.so                     \
		$(COMMON_LDFLAGS) $(TYPE_LDFLAGS) -nostartfiles                   \
		$(INJECTOR_OBJS) $(LIBCOMMON) $(VEXCORE_LIB)                      \
		$(PLTI_LIB) $(CSOLOADER_LIB)                                      \
		-llog -lm -o $@

$(LIBPTRACE): $(PTRACER_OBJS) $(LIBCOMMON) $(VEXCORE_LIB)
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(COMMON_LDFLAGS) $(TYPE_LDFLAGS) \
		$(PTRACER_OBJS) $(LIBCOMMON) $(VEXCORE_LIB) -llog -lm -o $@

$(LIBZYGISK_STRIPPED): $(LIBZYGISK)
	@mkdir -p $(dir $@)
	cp $< $@
	$(STRIP) --strip-all $@

$(LIBPTRACE_STRIPPED): $(LIBPTRACE)
	@mkdir -p $(dir $@)
	cp $< $@
	$(STRIP) --strip-all $@
