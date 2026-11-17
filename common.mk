ROOT_DIR ?= .
BUILD_TYPE ?= debug
API_LEVEL ?= 25
ARCH ?= arm64-v8a

VER_NAME ?= v2.5.0
# VER_CODE = commit count + 51: 17 commits were squashed away on 2026-09-02,
# the last pre-squash build was 591, so the sequence continues from there.
GIT_COUNT ?= $(shell git -C "$(ROOT_DIR)" rev-list HEAD --count 2>/dev/null || echo 540)
VER_CODE ?= $(shell expr $(GIT_COUNT) + 51)
COMMIT_HASH ?= $(shell git -C "$(ROOT_DIR)" rev-parse --verify --short HEAD 2>/dev/null || echo unknown)

MIN_KSU_VERSION ?= 10940
MIN_KSUD_VERSION ?= 11425
MIN_APATCH_VERSION ?= 10762

# INFO: Which root solution the binaries are built for: ksu (default) or
#       apatch. The two flavours ship as separate archives.
ROOT_IMPL ?= ksu

ifeq ($(ROOT_IMPL),apatch)
	ROOT_IMPL_DEF = -DROOT_IMPL_APATCH
else
	ROOT_IMPL = ksu
	ROOT_IMPL_DEF =
endif

MODULE_ID ?= rezygisk
MODULE_NAME ?= VexZygisk

NDK_VERSION ?= 29.0.13113456
ANDROID_HOME ?= $(HOME)/Android/Sdk
NDK_PATH ?= $(ANDROID_HOME)/ndk/$(NDK_VERSION)
TOOLCHAIN = $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64

ifeq ($(TERMUX_VERSION),)
	CC = $(TOOLCHAIN)/bin/clang
	CXX = $(TOOLCHAIN)/bin/clang++
	AR = $(TOOLCHAIN)/bin/llvm-ar
	STRIP = $(TOOLCHAIN)/bin/llvm-strip
	SYSROOT = $(TOOLCHAIN)/sysroot
else
	CC = clang
	CXX = clang++
	AR = llvm-ar
	STRIP = llvm-strip
endif

BUILD_DIR ?= $(ROOT_DIR)/build

# INFO: The Rust half of VexZygisk (rust/vexcore): the ELF symbol lookups and
#       the Zn module line parser. Built by cargo rather than by the compiler
#       these Makefiles drive, because cargo is what knows how to produce a
#       `no_std` staticlib for an Android target - and it is the same command a
#       developer runs by hand, so there is one way to build it and one place it
#       can be configured.
#
#       It is defined here rather than in either component's Makefile because
#       both link it: the loader and the tracer read ELF files the same way, and
#       the daemon parses the same module lines the loader's modules ship. One
#       archive, built once per build type, under this build's object directory.
#
#       The linker variable is named for cargo's benefit even though a staticlib
#       is assembled and never linked: a dependency that grows a link step later
#       should not fail with a message about a compiler nobody set up.
#
#       The copy at the end writes a temporary and renames it, and that is not
#       tidiness. The loader and the daemon are two sub-makes that the top-level
#       make runs side by side, both need this one archive, and both therefore
#       build it - cargo takes its own lock on the target directory, but the copy
#       that follows it is two cp processes writing one file, and a link that
#       arrives in the middle reads a half-written archive:
#
#         ld.lld: error: ... Archive::children failed: truncated or malformed
#         archive (offset to next archive member past the end of the archive)
#
#       A rename within a directory is atomic, so a reader gets either the
#       previous archive or the new one and never a mixture.
#
#       The temporary carries the shell's pid, and both commands share one line
#       because they have to share one shell:
#
#         - make turns a pair of dollars into one, and it is the shell that turns
#           the pair it receives into a number, so the pid is written as four
#           dollars. Two of them reach the shell as one, which is not a pid and
#           not even an expansion, and the two sub-makes then agree on the same
#           name again - the same collision, one level down.
#         - and make runs each line of a recipe in its own shell, so a cp and an
#           mv on separate lines are two different pids and the mv looks for a
#           file the cp never made. On one line they are one shell, one
#           expansion, one name.
#
#       Two sub-makes, two pids, two temporaries, and one rename that wins.
VEXCORE_DIR = $(ROOT_DIR)/rust/vexcore
VEXCORE_TARGET_DIR = $(BUILD_DIR)/obj/$(BUILD_TYPE)/vexcore-target
VEXCORE_LIB = $(BUILD_DIR)/obj/$(BUILD_TYPE)/vexcore/libvexcore.a
VEXCORE_INPUTS = $(shell find $(VEXCORE_DIR)/src -type f 2>/dev/null | sort) $(VEXCORE_DIR)/Cargo.toml $(VEXCORE_DIR)/Cargo.lock

.PHONY: vexcore
vexcore: $(VEXCORE_LIB)

$(VEXCORE_LIB): $(VEXCORE_INPUTS)
	@mkdir -p $(dir $@)
	cd $(VEXCORE_DIR) &&                                            \
		CARGO_TARGET_DIR=$(VEXCORE_TARGET_DIR)                      \
		CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$(TOOLCHAIN)/bin/aarch64-linux-android$(API_LEVEL)-clang \
		cargo build --release --locked --target aarch64-linux-android
	cp $(VEXCORE_TARGET_DIR)/aarch64-linux-android/release/libvexcore.a $@.tmp.$$$$ && mv -f $@.tmp.$$$$ $@

TARGET_arm64-v8a = aarch64-linux-android$(API_LEVEL)

ifneq ($(SYSROOT),)
	CC_ARCH = $(CC) --target=$(TARGET_$(ARCH)) --sysroot=$(SYSROOT)
	CXX_ARCH = $(CXX) --target=$(TARGET_$(ARCH)) --sysroot=$(SYSROOT)
else
	CC_ARCH = $(CC) --target=$(TARGET_$(ARCH))
	CXX_ARCH = $(CXX) --target=$(TARGET_$(ARCH))
endif

NDK_CFLAGS = -DANDROID -fdata-sections -ffunction-sections -funwind-tables \
	-fstack-protector-strong -no-canonical-prefixes -D_FORTIFY_SOURCE=2 \
	-Wformat -Werror=format-security
