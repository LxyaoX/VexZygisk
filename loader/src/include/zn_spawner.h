#ifndef ZN_SPAWNER_H
#define ZN_SPAWNER_H

/* What identifies HyperOS's app spawner. The whole Zygisk Next runtime of a boot
   hangs off this one question, and it is pure text and bytes, so the host tests
   can hold it still (tests/host/test_zn_spawner.c).

   Getting it wrong is not a degraded feature: entry() hands a process it does
   not recognise as the spawner to hook_functions(), whose JNI hooks crash the
   spawner and leave every application unable to start. Hence two answers, each
   used where it is the right one:

     - the image mapped at offset zero decides whether this process hosts the
       runtime at all (zn_hyos.h). It survives a rename and an unreadable
       /proc/self/exe: execve replaces the address space, and a process that
       merely forked from the spawner is never injected twice.
     - the executable's name only ever keeps a process out of the wrong branch;
       it cannot arm the runtime, since that needs the identity the scan
       produces.

   The image test is stricter on purpose: a mapping named like the spawner is
   only the spawner if the bytes are an ELF for this ABI. */

#include <elf.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "misc.h"

#define ZN_SPAWNER_BASE_NAME "hyos_spawner"

/* The image has to be one this process could execute, and the ABI is the one
   this copy was built for. ElfW already follows the ABI. */
#if defined(__aarch64__)
  #define ZN_SPAWNER_ELF_MACHINE EM_AARCH64
#elif defined(__arm__)
  #define ZN_SPAWNER_ELF_MACHINE EM_ARM
#elif defined(__x86_64__)
  #define ZN_SPAWNER_ELF_MACHINE EM_X86_64
#else
  #define ZN_SPAWNER_ELF_MACHINE EM_NONE
#endif

/* A path whose last component is the spawner's name as a whole component:
   ".../bin/hyos_spawner" matches, ".../bin/xhyos_spawner" and
   ".../bin/hyos_spawner.old" do not. The directory is not compared: what the
   platform calls the file is its business. */
static inline bool zn_spawner_path_is_image(const char *path, size_t len) {
  static const char kBase[] = ZN_SPAWNER_BASE_NAME;
  const size_t base_len = sizeof(kBase) - 1;

  if (path == NULL) return false;
  if (len <= base_len) return false;
  if (path[len - base_len - 1] != '/') return false;

  return memcmp(path + len - base_len, kBase, base_len) == 0;
}

/* Whether a mapping's path names the spawner's image, with the kernel's
   " (deleted)" suffix dropped: an OTA replaces the runtime image under a running
   system, and the suffix is part of the name.

   This is only the name half. A caller that can read the bytes asks
   zn_spawner_elf_is_image for the rest - the injector does, being inside the
   process; the monitor, reading somebody else's maps, has only this one. */
static inline bool zn_spawner_map_is_spawner(const char *path) {
  if (path == NULL) return false;

  return zn_spawner_path_is_image(path, strip_deleted_suffix(path, strlen(path)));
}

/* Whether a mapping starts with the spawner's executable header.
   `available_size` is how much may be read, and the caller is responsible for
   the mapping being readable: a PROT_NONE mapping is in the listing and must
   never be dereferenced. The header is copied out because the address is not
   promised to be aligned for ElfW(Ehdr). */
static inline bool zn_spawner_elf_is_image(const unsigned char *image, size_t available_size) {
  if (image == NULL) return false;
  if (available_size < sizeof(ElfW(Ehdr))) return false;

  ElfW(Ehdr) header;
  memcpy(&header, image, sizeof(header));

  if (memcmp(header.e_ident, ELFMAG, SELFMAG) != 0) return false;
  if (header.e_ident[EI_CLASS] != (sizeof(void *) == 8 ? ELFCLASS64 : ELFCLASS32)) return false;
  if (header.e_ident[EI_DATA] != ELFDATA2LSB) return false;
  if (header.e_type != ET_DYN && header.e_type != ET_EXEC) return false;

  return header.e_machine == ZN_SPAWNER_ELF_MACHINE;
}

#endif /* ZN_SPAWNER_H */
