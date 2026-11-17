#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>

#include "elf_util.h"
#include "logging.h"
#include "misc.h"

#include "zn_api.h"
#include "zn_loader.h"

/* The library a base address belongs to.

   The ZN API hands out a base address; the answer wanted here is the image's
   own identity - the mapping at offset zero - so the owning mapping is looked
   up in the process maps. A zero base names no library, which the reference
   reads as this process's own executable.

   The table is kept for an application and read fresh for a process the loader
   was injected into, whose own modules are mapping and unmapping while they
   load (zn_injected_target tells the two apart). Reading it costs a fork, and
   an application pays it once per module that targets it. A kept table can be
   behind: a miss drops it, so a library mapped after it was taken is found by
   the next call, and the answer a stale table gives in the meantime is "not
   mapped", which is the safe direction.
*/
static struct maps_info *zn_maps_cache = NULL;

static struct maps_info *zn_maps_for_lookup(void) {
  if (zn_injected_target) {
    struct maps_info *fresh = parse_maps_safe("self");

    if (fresh == NULL) {
      LOGE("Failed to scan this process's maps");

      /* INFO: No stale answer for an injected target, which is the one case
                the invariant above exists for: this process's own modules are
                mapping and unmapping under it, and a table from an earlier
                moment is exactly the freed-memory base the file refuses to
                hand out. The callers take NULL as "try again or fail", never
                as "here is where it was". */
      if (zn_maps_cache != NULL) {
        free_maps(zn_maps_cache);
        zn_maps_cache = NULL;
      }

      return NULL;
    }

    if (zn_maps_cache != NULL) free_maps(zn_maps_cache);
    zn_maps_cache = fresh;

    return zn_maps_cache;
  }

  if (zn_maps_cache == NULL) {
    zn_maps_cache = parse_maps_safe("self");

    if (zn_maps_cache == NULL) LOGE("Failed to scan this process's maps");
  }

  return zn_maps_cache;
}

/* INFO: Drop the kept table, so the next lookup reads the process as it is now.
            A miss is the only signal a caller gets that what it holds is
            behind. */
static void zn_forget_maps(void) {
  if (zn_maps_cache == NULL) return;

  free_maps(zn_maps_cache);
  zn_maps_cache = NULL;
}

static bool zn_map_for_base(uintptr_t base_addr, char **out_path, void **out_load_base) {
  bool found = false;

  /* INFO: Twice at most. A miss drops the kept table and asks again with a
            current one, because a library mapped after the table was taken is
            the one case a kept table answers wrongly. In a process the loader
            was injected into the table is current already and the second pass
            finds the same thing. */
  for (int attempt = 0; attempt < 2 && !found; attempt++) {
    struct maps_info *maps = zn_maps_for_lookup();
    if (maps == NULL) {
      LOGE("Failed to scan maps for the library at %p", (void *)base_addr);

      return false;
    }

    char exe[PATH_MAX] = { 0 };
    size_t exe_len = 0;

    if (base_addr == 0) {
      const ssize_t got = read_exe_path((int)getpid(), exe, sizeof(exe));

      if (got <= 0) {
        LOGE("Failed to resolve this process's own executable");

        return false;
      }

      exe_len = (size_t)got;
    }

    /* INFO: The image the mapping being looked at belongs to: the last
               offset-zero entry with the same identity, because the maps are
               listed by address and a file's first mapping is the one at offset
               zero. It is carried along the walk rather than searched for in it,
               which is what this did before - a second full scan of the table for
               every candidate, so a quadratic pass over a table that runs to
               hundreds of entries on a running system, to find something the walk
               had already passed. */
    const struct map_entry *head = NULL;

    for (size_t i = 0; i < maps->length && !found; i++) {
      struct map_entry *entry = &maps->maps[i];

      if (entry->inode == 0 || entry->path == NULL) continue;

      head = entry->offset == 0
                 ? entry
                 : (head != NULL && head->dev == entry->dev && head->inode == entry->inode ? head : NULL);

      if (base_addr == 0) {
        const size_t path_len = strip_deleted_suffix(entry->path, strlen(entry->path));

        if (entry->offset != 0 || path_len != exe_len || memcmp(entry->path, exe, exe_len) != 0) continue;
      } else {
        /* INFO: The module may pass the load base, the load bias or any address
                  inside the library, so all three are accepted here. */
        const uintptr_t load_base = entry->start - entry->offset;
        const bool inside = (base_addr >= entry->start && base_addr < entry->end) ||
                            base_addr == entry->start || base_addr == load_base;

        if (!inside) continue;
      }

      /* Any address inside the library names it, but the answer is the
         image's own mapping at offset zero; one whose image is not in the table
         at all still answers, as itself. */
      const struct map_entry *image = head != NULL ? head : entry;

      if (out_load_base != NULL) *out_load_base = (void *)(image->start - image->offset);

      if (out_path != NULL) {
        char *copy = strdup(image->path);

        if (copy == NULL) {
          LOGE("Failed to copy the path of the library at %p", (void *)base_addr);

          break;
        }

        /* INFO: A mapping of a file that was replaced while it was mapped
                  carries the suffix the kernel appends; the path a caller can
                  open is the one without it. */
        copy[strip_deleted_suffix(copy, strlen(copy))] = '\0';
        *out_path = copy;
      }

      found = true;
    }

    if (!found) zn_forget_maps();
  }

  if (!found) {
    LOGE("No library mapped at %p", (void *)base_addr);

    return false;
  }

  return true;
}

/* INFO: Whether a mapping's path is the library a caller named.

          The contract lets a resolver be named by bare soname ("libc.so") as
          well as by path, and the reference accepts three spellings of one
          answer: the map path in full, its last component, and - for anything
          that is not itself an absolute path - the end of it. The kernel
          appends " (deleted)" to a file that was replaced while it was mapped,
          so the map side is compared cleaned. */
static bool zn_path_matches_map(const char *want, const char *map_path) {
  if (want == NULL || want[0] == '\0' || map_path == NULL) return false;

  const size_t want_len = strlen(want);
  const size_t map_len = strip_deleted_suffix(map_path, strlen(map_path));

  if (map_len == want_len && memcmp(map_path, want, want_len) == 0) return true;

  size_t base_at = 0;

  for (size_t i = 0; i < map_len; i++) {
    if (map_path[i] == '/') base_at = i + 1;
  }

  if (map_len - base_at == want_len && memcmp(map_path + base_at, want, want_len) == 0) return true;

  if (want[0] == '/') return false;

  /* INFO: The suffix has to begin at a component boundary. Without that, a
            name like "libc.so" would also match ".../xyzlibc.so", and the
            resolver would hand back another library's symbols - the reference
            draws the line in the same place. */
  if (map_len <= want_len) return false;
  if (map_path[map_len - want_len - 1] != '/') return false;

  return memcmp(map_path + map_len - want_len, want, want_len) == 0;
}

/* INFO: The path of the library a caller named, taken from the mappings rather
          than from the string it passed. A soname is what a caller usually has
          and a path is what has to be read, and the mapping is where one
          becomes the other. */
static char *zn_mapped_lib_path(const char *want) {
  char *found = NULL;

  /* INFO: Twice at most, for the reason zn_map_for_base gives: a miss means the
            table is behind, and the answer it gives in the meantime is the safe
            one. */
  for (int attempt = 0; attempt < 2 && found == NULL; attempt++) {
    struct maps_info *maps = zn_maps_for_lookup();
    if (maps == NULL) return NULL;

    for (size_t i = 0; i < maps->length && found == NULL; i++) {
      struct map_entry *entry = &maps->maps[i];

      /* INFO: [heap], [stack] and the anonymous mappings are not files, and the
                image has to be the one the library starts at. */
      if (entry->inode == 0 || entry->offset != 0 || entry->path == NULL) continue;
      if (entry->path[0] == '[') continue;
      if (!zn_path_matches_map(want, entry->path)) continue;

      found = strdup(entry->path);
    }

    if (found == NULL) zn_forget_maps();
  }

  return found;
}

/* The three hook entries are refused rather than served: this fork ships no PLT
   or inline hooking engine, so a module that asks gets the answer the contract
   has for "could not hook" instead of a hook that would never fire. */
static int zn_plt_hook(void *base_addr, const char *symbol, void *hook_handler, void **original) {
  (void)base_addr;
  (void)symbol;
  (void)hook_handler;
  (void)original;

  LOGE("pltHook is not available in this build");

  return ZN_FAILED;
}

static int zn_inline_hook(void *target, void *addr, void **original) {
  (void)target;
  (void)addr;
  (void)original;

  LOGE("inlineHook is not available in this build");

  return ZN_FAILED;
}

static int zn_inline_unhook(void *target) {
  (void)target;

  return ZN_FAILED;
}

/* INFO: st_value is a link-time vaddr; the runtime address is the mapped ELF
         header (img->base) shifted by the difference to the first PT_LOAD's
         vaddr (img->bias), the same conversion getSymbAddress performs. */
static void *symbol_to_address(ElfImg *img, ElfW(Sym) *sym) {
  if (sym->st_value == 0) return NULL;

  return (void *)((uintptr_t)img->base + sym->st_value - img->bias);
}

/* INFO: Lookup order mirrors Zygisk Next: the parsed symbol tables are walked
           first - the file .symtab, then .dynsym, then the .gnu_debugdata
           mini-debug symbols - and an exact lookup that finds nothing there
           falls back to the hash tables of the dynamic symbol section. A prefix
           request is only ever served from those tables, which is why .dynsym
           has to be among them. */
static void *zn_symbol_lookup(struct ZnSymbolResolver *resolver, const char *name, bool prefix, size_t *size) {
  if (resolver == NULL || name == NULL) return NULL;

  ElfImg *img = (ElfImg *)resolver;

  size_t name_len = strlen(name);
  if (name_len == 0) return NULL;

  if (ElfImg_load_symbols(img)) {
    for (size_t i = 0; i < img->symtabs_count_; i++) {
      ElfW(Sym) *sym = img->symtabs_[i];

      const char *sym_name = getSymbName(img, sym);
      if (sym_name == NULL) continue;

      if (prefix ? (strncmp(sym_name, name, name_len) != 0) : (strcmp(sym_name, name) != 0)) continue;

      /* INFO: A match whose value converts to no address is not a hit the
                module can use, so it does not end the search - and *size is
                left alone rather than describing a symbol nobody can call. */
      void *addr = symbol_to_address(img, sym);
      if (addr == NULL) continue;

      if (size != NULL) *size = sym->st_size;

      return addr;
    }
  }

  /* INFO: Last resort for an exact lookup: the hash tables of the dynamic
             symbol section, resolved against the image base. */
  if (!prefix) {
    void *dynamic = (void *)getSymbAddress(img, name);
    if (dynamic != NULL) return dynamic;
  }

  return NULL;
}

static void zn_for_each_symbols(struct ZnSymbolResolver *resolver, bool (*callback)(const char *name, void *addr, size_t size, void *data), void *data) {
  if (resolver == NULL || callback == NULL) return;

  ElfImg *img = (ElfImg *)resolver;
  if (!ElfImg_load_symbols(img)) return;

  /* INFO: The seen-set is keyed on the symbol name, which is what identifies a
            symbol across tables. Now that the walk covers .symtab, .dynsym and
            the mini-debug table, one function is routinely described by all
            three; reporting it twice hands the module a second entry for an
            address it was already asked to hook, which its own duplicate check
            then refuses - so the repeat reads as a failure instead of as the
            same symbol. The name stays valid for the walk: it points into the
            mapped image or the decompressed mini-debug buffer. */
  char **seen = NULL;
  size_t seen_count = 0;
  size_t seen_capacity = 0;

  for (size_t i = 0; i < img->symtabs_count_; i++) {
    ElfW(Sym) *sym = img->symtabs_[i];

    const char *name = getSymbName(img, sym);
    if (name == NULL || name[0] == '\0') continue;

    void *addr = symbol_to_address(img, sym);
    if (addr == NULL) continue;

    bool duplicate = false;
    for (size_t j = 0; j < seen_count; j++) {
      if (strcmp(seen[j], name) == 0) {
        duplicate = true;

        break;
      }
    }

    if (duplicate) continue;

    if (seen_count == seen_capacity) {
      size_t capacity = seen_capacity == 0 ? 64 : seen_capacity * 2;

      char **grown = (char **)realloc(seen, capacity * sizeof(char *));
      if (grown == NULL) {
        LOGE("Failed growing the duplicate filter, reporting %s anyway", name);
      } else {
        seen = grown;
        seen_capacity = capacity;
      }
    }

    if (seen_count < seen_capacity) seen[seen_count++] = (char *)name;

    if (!callback(name, addr, sym->st_size, data)) break;
  }

  free(seen);
}

/* INFO: The resolver the contract asks for, built the way the reference builds
         one.

         The library has to be one this process has mapped, and the mapping is
         what supplies both the load base and the path the image is read from: a
         caller may name the library by soname, and the mapping is what that name
         resolved to. A library that is not mapped has no load base to hand back
         and no symbols to resolve, so the answer is a null resolver - which is
         also the answer the reference gives.

         A base address is tried first and the name second, in that order and
         for the same reason the reference does it: when the caller already knows
         where the library is, nothing about the name can change the answer, and
         only a base that names nothing falls back to it.

         Symbols are read here rather than on the first lookup, so a library
         whose symbols cannot be read is refused while the caller can still see
         why. */
static struct ZnSymbolResolver *zn_new_symbol_resolver(const char *path, void *base_addr) {
  char *lib_path = NULL;
  void *load_base = NULL;

  if (base_addr != NULL) {
    (void)zn_map_for_base((uintptr_t)base_addr, &lib_path, &load_base);
  }

  if (lib_path == NULL) {
    if (path == NULL) return NULL;

    lib_path = zn_mapped_lib_path(path);
    if (lib_path == NULL) {
      LOGE("No library named \"%s\" is mapped in this process", path);

      return NULL;
    }

    load_base = NULL;
  }

  struct ZnSymbolResolver *resolver = (struct ZnSymbolResolver *)ElfImg_create(lib_path, load_base);

  free(lib_path);

  if (resolver == NULL) return NULL;

  if (!ElfImg_load_symbols((ElfImg *)resolver)) {
    LOGE("Failed to read the symbols of the resolver's library");

    ElfImg_destroy((ElfImg *)resolver);

    return NULL;
  }

  return resolver;
}

static void zn_free_symbol_resolver(struct ZnSymbolResolver *resolver) {
  if (resolver == NULL) return;

  ElfImg_destroy((ElfImg *)resolver);
}

static void *zn_get_base_address(struct ZnSymbolResolver *resolver) {
  if (resolver == NULL) return NULL;

  return ((ElfImg *)resolver)->base;
}

/* INFO: The self handle is the loader's module entry, which carries the
         companion control socket when the module declared one. */
static int zn_connect_companion(void *handle) {
  int fd = zn_companion_connect(handle);
  if (fd < 0) LOGE("The module has no reachable companion process");

  return fd;
}

/* There is no process runtime in this build, so the entry that hands one out
   answers what it answers in a process that hosts none. */
static const void *zn_get_runtime(void) {
  return NULL;
}

/* The table every Zygisk Next module is served.

   One table and not one per version: a module older than ZN_MODULE_API_MIN is
   refused before it can call anything, so a second table would answer a
   question nobody asks. The layout is the contract - a field that moved would
   hand a module the wrong function pointer without failing to compile - and
   every offset of it is asserted in zygisk_next_api.h's users (zn_api.h keeps
   the gate, the daemon's C99 tests the layout through its own copy). */
static const struct ZygiskNextAPI zn_api = {
  .pltHook = zn_plt_hook,
  .inlineHook = zn_inline_hook,
  .inlineUnhook = zn_inline_unhook,

  .newSymbolResolver = zn_new_symbol_resolver,
  .freeSymbolResolver = zn_free_symbol_resolver,
  .getBaseAddress = zn_get_base_address,
  .symbolLookup = zn_symbol_lookup,
  .forEachSymbols = zn_for_each_symbols,

  .connectCompanion = zn_connect_companion,

  .getRuntime = zn_get_runtime
};

const struct ZygiskNextAPI *zn_get_api(void) {
  return &zn_api;
}
