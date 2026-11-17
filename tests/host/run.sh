#!/usr/bin/env bash
# INFO: The host test suite, shared by both workflows so a pull request runs
#       exactly what main runs once it merges.
#
#       The loader itself can never execute here, but the parts that fail
#       silently on a device are pure text and byte handling: the ELF reader
#       and the mini-debug decompressor behind it, the mountinfo parser that
#       decides what a revert would unmount, and the APatch package_config
#       parser that decides who gets root.
#
#       Every test pulls in the .c it exercises rather than linking against
#       it, so its static helpers are reachable; the include paths are the
#       ones those .c files expect.
set -eu

cd "$(dirname "$0")/../.."

# INFO: The tools the checks below call. Built here rather than expected to
#       already be there, so a fresh checkout runs this suite with nothing but a
#       Rust toolchain and a C compiler; the build is a no-op once they are up
#       to date.
cargo build --release --locked --manifest-path tools/Cargo.toml

# INFO: The loader and the daemon implement their own halves of the wire
#       protocol, and both still compile when one side drifts. This fails
#       first and cheapest, before anything is built.
./tools/target/release/check-protocol

# INFO: jni_hooks.h is generated and then committed, so a generator edit that
#       was never regenerated would go unnoticed until a device misbehaves.
./tools/target/release/check-generated

# INFO: The module scripts only ever run on a device, so a syntax error in one
#       of them would ride into the archive and surface as a module that fails
#       to start at boot, with nothing on the build side to have caught it.
#       Parsing needs no device and no root.
for script in module/src/*.sh module/src/apatch/*.sh; do
  bash -n "$script"
done

# INFO: -Werror on everything written in this tree, -w on the vendored XZ
#       decompressor: it is upstream code that is not maintained here, and
#       its warnings are not actionable.
#
#       elf_util.c reads the process maps to find a library's load base, so the
#       maps reader is linked in alongside it. misc.c pulls in socket_utils.c
#       for its logging path, hence the three together.
#       The ELF symbol lookups are Rust now (rust/vexcore), so the reader below
#       is linked against that archive. It is built for the host here, out of
#       the same sources the device build compiles with the same manifest -
#       only the target differs, and nothing under test can tell which one it
#       was built for.
cargo build --release --locked --manifest-path rust/vexcore/Cargo.toml
VEXCORE_LIB=rust/vexcore/target/release/libvexcore.a

# INFO: The crate's own tests, which cover what the C suite below cannot reach
#       from here: the tables a malformed image can name - a bucket index past
#       the symbol table, a name offset past its string table, a chain that ends
#       where it says it does. They also pin the two hashes against the values
#       the C versions produced, so a port that is off by a bit fails here
#       rather than as a symbol that silently does not resolve.
cargo test --release --locked --manifest-path rust/vexcore/Cargo.toml
cc -std=c18 -D_GNU_SOURCE -Wall -Wextra -Werror \
   -Itests/host -Iloader/src/include -Iloader/src/common \
   -Iloader/src/external/lzma \
   -c loader/src/common/elf_util.c -o /tmp/elf_util.o

cc -std=c18 -D_GNU_SOURCE -Wall -Wextra -Werror \
   -Itests/host -Iloader/src/include -Iloader/src/common \
   -c loader/src/common/misc.c -o /tmp/misc.o

cc -std=c18 -D_GNU_SOURCE -Wall -Wextra -Werror \
   -Itests/host -Iloader/src/include -Iloader/src/common \
   -c loader/src/common/socket_utils.c -o /tmp/socket_utils.o

cc -std=c18 -D_GNU_SOURCE -w \
   -DXZ_DEC_DYNALLOC=1 -DXZ_DEC_ANY_CHECK=1 -DXZ_INTERNAL_CRC32=1 \
   -DNOINLINE=noinline_for_stack \
   -Iloader/src/external/lzma \
   -c loader/src/external/lzma/xz_dec_lzma2.c -o /tmp/xz_lzma2.o

cc -std=c18 -D_GNU_SOURCE -w \
   -DXZ_DEC_DYNALLOC=1 -DXZ_DEC_ANY_CHECK=1 -DXZ_INTERNAL_CRC32=1 \
   -DNOINLINE=noinline_for_stack \
   -Iloader/src/external/lzma \
   -c loader/src/external/lzma/xz_dec_stream.c -o /tmp/xz_stream.o

cc -std=c18 -D_GNU_SOURCE -w \
   -DXZ_DEC_DYNALLOC=1 -DXZ_DEC_ANY_CHECK=1 -DXZ_INTERNAL_CRC32=1 \
   -DNOINLINE=noinline_for_stack \
   -Iloader/src/external/lzma \
   -c loader/src/external/lzma/xz_dec_bcj.c -o /tmp/xz_bcj.o

cc -std=c18 -D_GNU_SOURCE -Wall -Wextra -Werror \
   -Itests/host -Iloader/src/include -Iloader/src/common \
   -Iloader/src/external/lzma \
   tests/host/test_elf_util.c /tmp/elf_util.o /tmp/misc.o /tmp/socket_utils.o \
   /tmp/xz_lzma2.o /tmp/xz_stream.o /tmp/xz_bcj.o \
   $VEXCORE_LIB \
   -o /tmp/test_elf_util

./tools/target/release/make-debugdata /tmp/debugdata
/tmp/test_elf_util /tmp/debugdata /tmp/test_elf_util

cc -std=c18 -D_GNU_SOURCE -Wall -Wextra -Werror \
   -Itests/host -Iloader/src/include \
   tests/host/test_unmount.c -o /tmp/test_unmount
/tmp/test_unmount

# INFO: The same parser built the other way: the APatch flavour skips the
#       loop-device probe and matches module overlays by their /adb/modules
#       root alone, which is a different branch of carries_root_trace.
cc -std=c18 -D_GNU_SOURCE -Wall -Wextra -Werror -DROOT_IMPL_APATCH \
   -Itests/host -Iloader/src/include \
   tests/host/test_unmount.c -o /tmp/test_unmount_apatch
/tmp/test_unmount_apatch

# INFO: The maps hiding is the same shape: replacing a mapping needs a
#       device, but which mappings qualify is decided on the path alone,
#       and getting that wrong either leaves every module named or turns
#       ashmem and the ART images into private copies.
cc -std=c18 -D_GNU_SOURCE -Wall -Wextra -Werror \
   -Itests/host -Iloader/src/include \
   tests/host/test_hiding.c -o /tmp/test_hiding
/tmp/test_hiding

cc -std=c18 -D_GNU_SOURCE -Wall -Wextra -Werror \
   -Itests/host -Iloader/src/include -Izygiskd/src -Izygiskd/src/root_impl \
   tests/host/test_apatch.c -o /tmp/test_apatch
/tmp/test_apatch
