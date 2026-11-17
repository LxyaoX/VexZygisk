# INFO: The same sources build for two root solutions. FLAVOR_DIR keeps the
#       build trees apart so the ksu and apatch flavours can live side by side
#       (and so a cached .done from one cannot mask the other).
FLAVOR_DIR ?=
BUILD_DIR := $(CURDIR)/build$(FLAVOR_DIR)

include common.mk

# INFO: common.mk carries the rule that builds the Rust archive, and a rule is
#       what decides the default goal: make takes the first target of the first
#       rule it read, and an include is read before the rest of this file. So
#       without this line a bare `make` would build libvexcore.a and stop, and
#       the packaging step would then look for the binaries it never got.
#
#       The goal is the one this Makefile has always defaulted to.
.DEFAULT_GOAL := tools
OBJ_DIR = $(BUILD_DIR)/obj/$(BUILD_TYPE)
MODULE_OUT = $(BUILD_DIR)/module/$(BUILD_TYPE)
ZIP_DIR = $(BUILD_DIR)/out

ZKSU_VERSION = $(VER_NAME)-$(VER_CODE)-$(COMMIT_HASH)-$(BUILD_TYPE)

ZIP_NAME = $(MODULE_NAME)-$(VER_NAME)-$(VER_CODE)-$(COMMIT_HASH)-$(BUILD_TYPE).zip
ZIP_FILE = $(ZIP_DIR)/$(ZIP_NAME)

# INFO: Only the per-flavour templates and the archive differ; the binaries
#       themselves already carry the ROOT_IMPL macro. The APatch copies of the
#       module files drop the KernelSU-only managedFeatures flag, rewrite the
#       update entry to the APatch channel, and leave out the post-mount.d
#       cleanup.
#
#       late-load.sh is per-flavour too: it is the stage a late-loaded
#       KernelSU runs, and the APatch installer neither extracts it nor has a
#       stage to install it into. Shipping it there leaves a script in the
#       archive that nothing can ever run.
#       action.sh is shared as well: both managers show a module's action button
#       when one is present, and both flavours can be left stopped by an update.
SHARED_SCRIPTS = module/src/verify.sh module/src/rezygisk.sh module/src/action.sh

# INFO: The SELinux rules differ between the flavours only in the name of the
#       root daemon's domain, so they are kept as a single template and
#       substituted into the module tree at build time instead of being
#       maintained as two copies under module/src. One thing to edit, one
#       thing to review.
SEPOLICY_TEMPLATE = module/src/sepolicy.rule.in

# INFO: ROOT_IMPL names the build flavour, which is not the domain name: the
#       APatch flavour still runs under the "su" context.
SEPOLICY_ROOT_DOMAIN = ksu
ifeq ($(ROOT_IMPL),apatch)
	SEPOLICY_ROOT_DOMAIN = su
endif

ifeq ($(ROOT_IMPL),apatch)
	CUSTOMIZE_SRC = module/src/apatch/customize.sh
	MODULE_PROP_SRC = module/src/apatch/module.prop
	UNINSTALL_SRC = module/src/apatch/uninstall.sh
	MODULE_SCRIPTS = $(SHARED_SCRIPTS)
else
	CUSTOMIZE_SRC = module/src/customize.sh
	MODULE_PROP_SRC = module/src/module.prop
	UNINSTALL_SRC = module/src/uninstall.sh
	MODULE_SCRIPTS = $(SHARED_SCRIPTS) module/src/late-load.sh
endif

ifeq ($(TERMUX_VERSION),)
	ADB_CMD := adb push $(ZIP_FILE) /data/local/tmp && adb shell 
	INSTALL_PATH := /data/local/tmp/$(ZIP_NAME)
	REBOOT_CMD := adb reboot
else
	INSTALL_PATH := $(ZIP_FILE)
	REBOOT_CMD := su -c reboot
endif

# INFO: Each root solution ships its own module installer, so which one a
#       `make install` drives follows the flavour this tree is configured for
#       rather than being spelled out in the target's name.
ifeq ($(ROOT_IMPL),apatch)
	INSTALL_CMD := /data/adb/ap/bin/apd module install
else
	INSTALL_CMD := /data/adb/ksud module install
endif

LOADER_DONE = $(OBJ_DIR)/loader/.done
ZYGISKD_DONE = $(OBJ_DIR)/zygiskd/.done
MODULE_DONE = $(BUILD_DIR)/module-$(BUILD_TYPE).done

LOADER_INPUTS = common.mk loader/Makefile \
        $(shell find loader/src -type f | sort)

# INFO: zygiskd compiles against the headers in loader/src/include (see the
#       -I in zygiskd/Makefile), so a change there has to rebuild it as well.
#       Only the headers are listed: the rest of loader/src reaches zygiskd
#       through LOADER_DONE, which already depends on all of it.
ZYGISKD_INPUTS = common.mk zygiskd/Makefile \
        $(shell find zygiskd/src -type f | sort) \
        $(shell find loader/src/include -type f 2>/dev/null | sort)

# INFO: The build tools are Rust now, built once into the crate's target
#       directory and then called by path.
TOOLS_DIR = $(CURDIR)/tools
TOOLS_BIN = $(TOOLS_DIR)/target/release

SIGN = $(TOOLS_BIN)/sign

TOOLS_INPUTS = $(TOOLS_DIR)/Cargo.toml $(TOOLS_DIR)/Cargo.lock \
        $(shell find $(TOOLS_DIR)/src -type f | sort)

MODULE_INPUTS = $(TOOLS_INPUTS) \
        $(shell find module/src -type f | sort) \
        $(wildcard module/private_key module/public_key)

.PHONY: debug release all apatch apatch-debug build clean install installAndReboot \
        tools tools-test analyzer

# INFO: The Rust tools the packaging step calls. `cargo build --release` is what
#       puts them at $(TOOLS_BIN); a developer who already built them pays only
#       for the up-to-date check.
tools:
	@$(MAKE) -C $(TOOLS_DIR) build-host

tools-test:
	@$(MAKE) -C $(TOOLS_DIR) test-host

debug:
	$(MAKE) BUILD_TYPE=debug BUILD_DIR=$(BUILD_DIR) build

release:
	$(MAKE) BUILD_TYPE=release BUILD_DIR=$(BUILD_DIR) build

all: debug release

# INFO: The APatch flavour lives in its own tree (build-apatch) and ships
#       under its own archive name, so a single workflow run yields both.
apatch:
	$(MAKE) release ROOT_IMPL=apatch MODULE_NAME=VexZygisk-APatch FLAVOR_DIR=-apatch

apatch-debug:
	$(MAKE) debug ROOT_IMPL=apatch MODULE_NAME=VexZygisk-APatch FLAVOR_DIR=-apatch

build: $(ZIP_FILE)

$(LOADER_DONE): $(LOADER_INPUTS)
	$(MAKE) -C loader BUILD_TYPE=$(BUILD_TYPE) BUILD_DIR=$(BUILD_DIR) ZKSU_VERSION=$(ZKSU_VERSION)
	@mkdir -p $(dir $@)
	@touch $@

$(ZYGISKD_DONE): $(ZYGISKD_INPUTS)
	$(MAKE) -C zygiskd BUILD_TYPE=$(BUILD_TYPE) BUILD_DIR=$(BUILD_DIR) ZKSU_VERSION=$(ZKSU_VERSION)
	@mkdir -p $(dir $@)
	@touch $@

$(MODULE_DONE): $(LOADER_DONE) $(ZYGISKD_DONE) $(MODULE_INPUTS)

	@rm -rf $(MODULE_OUT)
	@mkdir -p $(MODULE_OUT)

	@echo "Copying module files..."
	@cp $(MODULE_SCRIPTS) $(MODULE_OUT)/
	@sed 's/@ROOT_DOMAIN@/$(SEPOLICY_ROOT_DOMAIN)/g' $(SEPOLICY_TEMPLATE) > $(MODULE_OUT)/sepolicy.rule

	@echo "Customizing module.prop..."
	@sed -e 's/$${moduleId}/$(MODULE_ID)/g'                                             \
	    -e 's/$${moduleName}/$(MODULE_NAME)/g'                                          \
	    -e 's/$${versionName}/$(VER_NAME) ($(VER_CODE)-$(COMMIT_HASH)-$(BUILD_TYPE))/g' \
	    -e 's/$${versionCode}/$(VER_CODE)/g'                                            \
	    $(MODULE_PROP_SRC) > $(MODULE_OUT)/module.prop

	@echo "Customizing scripts..."
	@for pair in "module/src/post-fs-data.sh:post-fs-data.sh" "$(UNINSTALL_SRC):uninstall.sh" "$(CUSTOMIZE_SRC):customize.sh"; do \
		src=$${pair%%:*}; dst=$${pair##*:}; \
		sed \
		    -e 's/@MIN_KSU_VERSION@/$(MIN_KSU_VERSION)/g' \
		    -e 's/@MIN_KSUD_VERSION@/$(MIN_KSUD_VERSION)/g' \
		    -e 's/@MIN_APATCH_VERSION@/$(MIN_APATCH_VERSION)/g' \
		$$src > $(MODULE_OUT)/$$dst; \
	done

	@echo "Copying binaries..."
	@mkdir -p $(MODULE_OUT)/bin/$(ARCH) $(MODULE_OUT)/lib/$(ARCH)
	@cp $(OBJ_DIR)/zygiskd/$(ARCH)/zygiskd $(MODULE_OUT)/bin/$(ARCH)/zygiskd
	@cp $(OBJ_DIR)/loader/$(ARCH)/stripped/libzygisk.so $(MODULE_OUT)/lib/$(ARCH)/libzygisk.so
	@cp $(OBJ_DIR)/loader/$(ARCH)/stripped/libzygisk_ptrace.so $(MODULE_OUT)/lib/$(ARCH)/libzygisk_ptrace.so

	@if [ -f module/private_key ] && [ -f module/public_key ]; then                 \
		echo "Signing module...";                                                   \
		$(SIGN) $(MODULE_OUT) module/private_key module/public_key;                  \
	else                                                                            \
	    echo "No private key found, skipping signing...";                           \
		$(SIGN) --no-sign $(MODULE_OUT);                                            \
	fi

	@mkdir -p $(dir $@)
	@touch $@

$(ZIP_FILE): $(MODULE_DONE)
	@mkdir -p $(ZIP_DIR)
	@rm -f $@

	@echo "Creating ZIP file..."
	@cd $(MODULE_OUT) && zip -r9 $@ . -x '*.DS_Store' > /dev/null

install: build
	$(ADB_CMD)su -c '$(INSTALL_CMD) $(INSTALL_PATH)'

installAndReboot: install
	$(REBOOT_CMD)

# INFO: The same build through clang's static analyzer, which walks the paths a
#       normal build only warns about. Nothing is packaged: the analyzer writes
#       reports, not objects, so the link steps have nothing to produce and -k
#       is what keeps the run going past them.
analyzer:
	$(MAKE) -C loader clean BUILD_TYPE=debug BUILD_DIR=$(BUILD_DIR)
	$(MAKE) -C zygiskd clean BUILD_TYPE=debug BUILD_DIR=$(BUILD_DIR)
	@rm -f $(LOADER_DONE) $(ZYGISKD_DONE)
	@$(MAKE) -k BUILD_TYPE=debug ARCH=arm64-v8a $(LOADER_DONE) $(ZYGISKD_DONE) \
		CC='$(TOOLCHAIN)/bin/clang --analyze -Wno-unused-command-line-argument -Xanalyzer -analyzer-output=text'

clean:
	rm -rf $(CURDIR)/build $(CURDIR)/build-apatch
	$(MAKE) -C loader clean BUILD_DIR=$(BUILD_DIR)
	$(MAKE) -C zygiskd clean BUILD_DIR=$(BUILD_DIR)
