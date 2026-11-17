#ifndef ROOT_MOUNTS_H
#define ROOT_MOUNTS_H

/* What counts as a root trace in a mount table. The loader (injector/unmount.c)
   and the daemon (utils.c) both walk /proc/<pid>/mountinfo and must drop the
   same set, so the rule lives here once: a mount one walker drops and the other
   keeps is a half-hidden process. */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define MOUNT_SOURCE_LOOP "/dev/block/loop"
#define ROOT_MODULES_DIR "/data/adb/modules"
#define ROOT_MODULES_ROOT "/adb/modules"

#define MOUNT_FIELD_MAX 4096
#define MOUNT_TYPE_MAX 128

/* The scanf widths below are these limits minus one; the check keeps the pair
   honest. C11 has _Static_assert, the daemon's c99 does not. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(MOUNT_FIELD_MAX == 4096, "the scanf width %4095s must follow MOUNT_FIELD_MAX");
_Static_assert(MOUNT_TYPE_MAX == 128, "the scanf width %127s must follow MOUNT_TYPE_MAX");
#else
typedef char mount_field_max_matches_scanf_width[(MOUNT_FIELD_MAX == 4096) ? 1 : -1];
typedef char mount_type_max_matches_scanf_width[(MOUNT_TYPE_MAX == 128) ? 1 : -1];
#endif

/* One parsed mountinfo line. The id is carried for both walkers so they can
   share the struct; only the loader orders by it. */
struct mount_entry {
  unsigned int id;
  char *root;
  char *target;
  char *source;
};

/* Splits one line in place:
     36 35 98:0 /root /target rw,... - type source rw,...
   Cut at " - ", the only delimiter that cannot appear inside a field, so a long
   path is not dropped as oversized. False for a line that is not a mount: no
   separator, or no source after it (pseudo-filesystems). */
static inline bool mount_entry_split(char *line, unsigned int *id,
                                     char *root, char *target,
                                     char *type, char *source) {
  char *separator = strstr(line, " - ");
  if (separator == NULL) return false;

  *separator = '\0';

  if (sscanf(line, "%u %*u %*u:%*u %4095s %4095s", id, root, target) != 3) return false;
  if (sscanf(separator + 3, "%127s %4095s", type, source) != 2) return false;

  return true;
}

/* `path` equals `prefix` or sits directly under it. A bare prefix test would
   also match a sibling such as /data/adb/modules_extra. */
static inline bool mount_path_at_or_under(const char *path, const char *prefix) {
  size_t len = strlen(prefix);

  if (strncmp(path, prefix, len) != 0) return false;

  char next = path[len];

  return next == '\0' || next == '/';
}

/* KernelSU keeps the modules on a loop device and that name is the source of
   every mount under the module directory. APatch mounts them as a plain
   overlay, so only the KernelSU flavour looks for it. */
static inline bool mount_is_module_loop_source(const char *target, const char *source) {
#ifdef ROOT_IMPL_APATCH
  (void) target;
  (void) source;

  return false;
#else
  return strcmp(target, ROOT_MODULES_DIR) == 0 &&
         strncmp(source, MOUNT_SOURCE_LOOP, strlen(MOUNT_SOURCE_LOOP)) == 0;
#endif
}

/* The loop source both walkers look up before deciding: without it the clean
   namespace would miss every mount whose source is the loop device. NULL on
   APatch, where there is no such mount. Logging is the caller's. */
static inline const char *mount_find_loop_source(const struct mount_entry *entries, size_t count) {
  for (size_t i = 0; i < count; i++) {
    if (!mount_is_module_loop_source(entries[i].target, entries[i].source)) continue;

    return entries[i].source;
  }

  return NULL;
}

/* The overlay source each root solution reports; the flavour is fixed at build
   time, so only the matching names are compiled in. */
#ifdef ROOT_IMPL_APATCH
  static const char *const kRootSources[] = { "APatch", "kpatch" };
  #define ROOT_SOURCE_COUNT 2
#else
  static const char *const kRootSources[] = { "KSU" };
  #define ROOT_SOURCE_COUNT 1
#endif

/* The whole decision in one place: whether this mount is one the process loses.
   `loop_source` is the module store's loop device, NULL when there is none
   (APatch) - hence the NULL check rather than a strcmp against it. */
static inline bool mount_carries_root_trace(const char *root, const char *target,
                                            const char *source, const char *loop_source) {
  if (mount_path_at_or_under(root, ROOT_MODULES_ROOT)) return true;
  if (mount_path_at_or_under(target, ROOT_MODULES_DIR)) return true;

  for (size_t i = 0; i < ROOT_SOURCE_COUNT; i++) {
    if (strcmp(source, kRootSources[i]) == 0) return true;
  }

  return loop_source != NULL && strcmp(source, loop_source) == 0;
}

#endif /* ROOT_MOUNTS_H */
