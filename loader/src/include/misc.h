#ifndef MISC_H
#define MISC_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <limits.h>
#include <sys/types.h>
#include <unistd.h>

/* Every uid is userId * 100000 + appId, and it is the appId that root
   implementations key off. A later user - Private Space included - shifts the
   uid by whole 100000s, so reduce before comparing. */
#define APP_ID(uid) ((uid) % 100000)

#define IS_ISOLATED_SERVICE(uid)      \
  (APP_ID(uid) >= 90000)

/* The kernel appends " (deleted)" to the link target of an executable whose
   file was replaced while running - an OTA is the usual cause - and the suffix
   is part of the target. Returns the length to terminate the path at. The test
   is strict so a path consisting of the suffix alone cannot come back empty. */
static inline size_t strip_deleted_suffix(const char *path, size_t len) {
  static const char kDeletedSuffix[] = " (deleted)";
  size_t suffix_len = sizeof(kDeletedSuffix) - 1;

  if (len > suffix_len && memcmp(path + len - suffix_len, kDeletedSuffix, suffix_len) == 0) {
    return len - suffix_len;
  }

  return len;
}

/* Reads /proc/<pid>/exe into `buf` with the suffix dropped and a terminator
   written; returns its length, or -1 when the link could not be read. Only what
   a failure means stays with the caller: a /proc sweep stays silent, a reader
   handed one specific pid reports it. */
static inline ssize_t read_exe_path(int pid, char *buf, size_t size) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d/exe", pid);

  ssize_t len = readlink(path, buf, size);
  if (len <= 0) return -1;

  /* Filled to the last byte means the target did not fit, and a clamped copy
     would be a different path that full-path compares then answer wrongly. */
  if ((size_t)len >= size) return -1;

  len = (ssize_t)strip_deleted_suffix(buf, (size_t)len);
  buf[len] = '\0';

  return len;
}

struct kernel_version {
  uint8_t major;
  unsigned int minor;
  unsigned int patch;
};

struct map_entry {
  uintptr_t start;
  uintptr_t end;
  int perms;
  bool is_private;
  uintptr_t offset;
  dev_t dev;
  ino_t inode;
  char *path;
};

struct maps_info {
  struct map_entry *maps;
  size_t length;
};

/* One entry of a maps listing, valid only while the line it was read from is
   alive: path points into it, so a visitor that keeps the entry has to copy the
   path. False stops the walk early, which is not a failure. */
typedef bool (*maps_visitor)(const struct map_entry *map, void *userdata);

int parse_int(const char *str);

struct kernel_version parse_kversion(void);

/* Safe reads hand the maps out through a forked child, so /proc/self/maps keeps
   its access time. Use them in any injected process; only the tracer, the
   daemon and the monitor read plainly. */
struct maps_info *parse_maps_safe(const char *pid);

struct maps_info *parse_maps(const char *pid);

void free_maps(struct maps_info *maps);

/* parse_maps_safe without the table: entries reach the visitor as they are
   read. False when the maps could not be read at all. */
bool scan_maps_safe(const char *pid, maps_visitor visit, void *userdata);

#endif /* MISC_H */
