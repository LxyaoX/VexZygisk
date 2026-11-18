#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "hiding.h"
#include "logging.h"
#include "misc.h"
#include "zygisk_paths.h"

/* INFO: A prefix rather than a whole path: a file deleted after it was mapped
         keeps its name and only gains a " (deleted)" suffix, and which module
         owns a library makes no difference to whether it is a trace. */
#define ADB_PREFIX "/data/adb/"

/* INFO: Whether `path` is exactly `name`, with the suffix a mapping keeps once
         the file behind it is gone counted as no part of the name. A prefix
         compare answers a different question: a library whose path merely
         starts with the injector's is somebody else's mapping and must not be
         replaced. */
static bool path_is(const char *path, const char *name) {
  size_t name_len = strlen(name);

  return strip_deleted_suffix(path, strlen(path)) == name_len &&
         memcmp(path, name, name_len) == 0;
}

/* Whether this process has to stop naming `map` in its own maps listing.

   Named for the question, not for where the mapping comes from: the answer is
   yes for the injector's own library and for a module library, and no for
   everything else under the module directory.

   The device decides a path: a module library only counts while it sits on
   /data, since a bind mount or an sdcard can put the same names elsewhere.

   Shared mappings are left alone: turning one into a private copy would leave
   the process holding a stale view of someone else's memory.

   The injector's own mapping is included, and must be: the target's linker
   loaded it and carries a module entry naming it. Replacing the mapping this
   code runs from is safe because the copy is the same bytes at the same
   address, moved in with its permissions already set. */
static bool map_is_a_trace(const struct map_entry *map, dev_t data_dev) {
  const char *path = map->path;

  if (path == NULL) return false;

  if (!map->is_private) return false;

  /* INFO: Checked before the module directory is excluded below, since the
            injector lives inside it. It stays mapped until the unloader runs,
            and the unloader keeps it mapped - see hook.c for why. */
  if (path_is(path, ZYGISK_LOADER_LIB)) return true;

  if (map->dev != data_dev) return false;

  if (strncmp(path, ZYGISK_MODULE_DIR "/", sizeof(ZYGISK_MODULE_DIR "/") - 1) == 0) return false;

  return strncmp(path, ADB_PREFIX, sizeof(ADB_PREFIX) - 1) == 0;
}

/* INFO: One mapping selected for hiding, collected while the maps stream is
         read and acted on after it has closed. A hidden process is a running
         one: replacing a mapping with mremap splits and merges the vmas the
         stream is still walking, and an entry read from a table that changed
         under its reader describes a range this code would then mprotect or
         remap blind - which is how a read-only remnant can land on memory as
         unrelated as bionic's own atexit array and take a process tree down
         with it (issue #30). */
struct hide_target {
  void *start;
  size_t size;
  int perms;
  bool made_readable;
  char *path;
};

struct hide_state {
  dev_t data_dev;
  struct hide_target *targets;
  size_t count;
  size_t capacity;
};

/* INFO: The one place the collected paths are given back. The walk ends two
         ways, and each used to free the list in its own words - so a change to
         one of them was a leak on a device and nothing else. */
static void free_hide_state(struct hide_state *state) {
  for (size_t i = 0; i < state->count; i++) free(state->targets[i].path);

  free(state->targets);

  state->targets = NULL;
  state->count = 0;
  state->capacity = 0;
}

static bool collect_one_map(const struct map_entry *map, void *userdata) {
  struct hide_state *state = userdata;

  if (!map_is_a_trace(map, state->data_dev)) return true;

  if (state->count == state->capacity) {
    size_t capacity = state->capacity == 0 ? 8 : state->capacity * 2;

    struct hide_target *grown = realloc(state->targets, capacity * sizeof(struct hide_target));
    if (grown == NULL) {
      PLOGE("allocate the hide list");

      return false;
    }

    state->targets = grown;
    state->capacity = capacity;
  }

  struct hide_target *target = &state->targets[state->count];

  target->start = (void *)map->start;
  target->size = (size_t)(map->end - map->start);
  target->perms = map->perms;
  target->made_readable = (map->perms & PROT_READ) == 0;
  target->path = strdup(map->path);

  if (target->path == NULL) {
    PLOGE("allocate the path of [%s]", map->path);

    return false;
  }

  state->count++;

  return true;
}

/* The name the copy is given, and the reason it is that name.

   An anonymous executable mapping is a signature of its own - a scan for
   PROT_EXEC regions with nothing behind them finds it - so the copy is mapped
   from a memfd named after the runtime's own JIT cache: an executable mapping
   every process already carries.

   "jit-zygote-cache" rather than "jit-cache" because the name carrying "zygote"
   is the zygote's own, so an application is the last place a scan expects a
   second one. Every replacement in a process is a range of the same memfd,
   since the inode behind each name has to agree with the others. */
#define HIDE_MEMFD_NAME "jit-zygote-cache"

/* INFO: memfd_create() only reaches bionic from API 30, while common.mk builds
         against an older level; the raw syscall is what the daemon uses too. */
#ifndef MFD_CLOEXEC
  #define MFD_CLOEXEC 0x0001U
#endif

/* INFO: A kernel from 6.3 on refuses to map a memfd executable unless it was
         created with this flag, and a kernel older than that refuses the flag
         itself. It is tried first and dropped when the call rejects it. */
#ifndef MFD_EXEC
  #define MFD_EXEC 0x0010U
#endif

/* INFO: The one memfd every replacement in this process is mapped from, how
         much of it is in use, and whether it turned out to be usable at all.
         All three belong to the process: a forked application inherits neither
         the replacements nor this cache, so it starts from its own. */
static int hide_memfd = -1;
static off_t hide_memfd_end = 0;
static bool hide_memfd_refused = false;

/* INFO: Set once the descriptor has been closed after a pass. The mappings
         still name /memfd:jit-zygote-cache and share one inode, so a later
         pass must not open a second memfd under that name - two inodes with
         the same name are exactly what the inode-consistency check flags. */
static bool hide_memfd_sealed = false;

static int hide_backing_memfd(void) {
  if (hide_memfd != -1) return hide_memfd;
  if (hide_memfd_refused || hide_memfd_sealed) return -1;

  int fd = (int)syscall(__NR_memfd_create, HIDE_MEMFD_NAME, MFD_CLOEXEC | MFD_EXEC);
  if (fd == -1 && errno == EINVAL) fd = (int)syscall(__NR_memfd_create, HIDE_MEMFD_NAME, MFD_CLOEXEC);

  if (fd == -1) {
    PLOGE("create the backing memfd");

    hide_memfd_refused = true;

    return -1;
  }

  /* INFO: Whether this process may map the memfd executable is policy, and the
            answer picks the backing for every replacement that follows. It is
            asked once, on one page. The grant that lets a process make
            anonymous memory executable is not the one that covers a file, so a
            device where the anonymous copy works can still refuse this one -
            and there the older behaviour is the fallback rather than a
            failure, or hiding would stop working altogether. */
  size_t page = (size_t)sysconf(_SC_PAGESIZE);
  void *probe = MAP_FAILED;

  if (ftruncate(fd, (off_t)page) != -1)
    probe = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  bool usable = probe != MAP_FAILED && mprotect(probe, page, PROT_EXEC) == 0;

  if (probe != MAP_FAILED) munmap(probe, page);

  if (!usable) {
    PLOGE("map a copy out of the backing memfd");

    close(fd);

    hide_memfd_refused = true;

    return -1;
  }

  hide_memfd = fd;

  return fd;
}

/* INFO: A library that is still mapped - the injector itself and every module
         library the loader abandons rather than unloads - names its own file in
         /proc/self/maps. The mapping is replaced with a copy of the same bytes
         at the same address, so the library keeps running out of the same place
         and the name is gone.

         One exit for what has been taken, and the taking starts at the copy:
         everything before it returns where it stands, and the three failures
         after it go through `cleanup:` instead of undoing the earlier steps
         each in their own words - which is the shape that leaves a mapping
         readable, or a copy behind, the once a path is edited and its
         neighbours are not. */
static bool hide_map(struct hide_target *target) {
  size_t size = target->size;

  /* INFO: Whether this pass is the reason the original is readable. Two of the
            failures below have to put the permissions back and the third must
            not - it is the one where the call that changes them failed - so the
            cleanup asks this and not the map's own permissions. */
  bool original_made_readable = false;

  /* INFO: Where the copy comes from: the memfd when this process may map one
            executable, an anonymous mapping when it may not. Only this choice
            differs between the two - everything below treats the copy the same
            way, and the anonymous one is what this always used to be. */
  int fd = hide_backing_memfd();
  off_t offset = hide_memfd_end;

  void *copy;

  if (fd != -1) {
    /* INFO: A fresh range at the end of the memfd. Nothing else is written
              there until a replacement has actually landed, so a failure costs
              the process nothing but the space, and the file is only ever
              grown to the end of what is in use - a later ftruncate cannot
              shorten a range an earlier replacement is still mapped from. */
    if (ftruncate(fd, offset + (off_t)size) == -1) {
      PLOGE("grow the backing memfd for [%s]", target->path);

      return false;
    }

    copy = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
    if (copy == MAP_FAILED) {
      PLOGE("map a copy of [%s] out of the memfd", target->path);

      return false;
    }
  } else {
    copy = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (copy == MAP_FAILED) {
      PLOGE("allocate a copy of [%s]", target->path);

      return false;
    }
  }

  /* INFO: A mapping without PROT_READ cannot be copied out of, so it is made
            readable for the duration of the copy and put back afterwards. */
  if (target->made_readable) {
    if (mprotect(target->start, size, target->perms | PROT_READ) == -1) {
      PLOGE("make [%s] readable", target->path);

      goto cleanup;
    }

    original_made_readable = true;
  }

  memcpy(copy, target->start, size);

  /* INFO: The copy receives its final permissions before it is moved into
            place. A replacement that lands with the permissions it will keep
            from its first byte needs no mprotect after the move - which is
            the window where an executable segment of a running process is
            neither executable nor writable, and where a second thread walking
            memory can find a mapping that lies about itself. */
  if (mprotect(copy, size, target->perms) == -1) {
    PLOGE("set the permissions of the copy of [%s]", target->path);

    goto cleanup;
  }

  if (mremap(copy, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, target->start) == MAP_FAILED) {
    PLOGE("move the copy of [%s] over the original", target->path);

    goto cleanup;
  }

  /* INFO: Only now does the range become part of the file's used length. The
            copy is at target->start from here on, so this path must not reach
            the cleanup - returning rather than falling through is what keeps a
            good replacement from being unmapped one line later. */
  if (fd != -1) hide_memfd_end = offset + (off_t)size;

  LOGD("Hid [%s]", target->path);

  return true;

cleanup:
  /* INFO: The copy goes first and the original's permissions second, in that
            order: restoring is the call that can fail, and a failure there
            should not be the reason a copy of somebody's memory stays mapped. */
  munmap(copy, size);

  if (original_made_readable && mprotect(target->start, size, target->perms) == -1)
    PLOGE("restore the permissions of [%s]", target->path);

  return false;
}

/* INFO: Set once the process's own mappings have been replaced, so the teardown
         can skip a pass that could only come back empty. Per process, like
         everything else here: a forked application does not inherit the
         replacement, it inherits the mappings that were replaced. */
static bool module_maps_were_hidden = false;

bool module_maps_hidden(void) {
  return module_maps_were_hidden;
}

bool hide_module_maps(void) {
  struct stat data;
  if (stat("/data", &data) == -1) {
    PLOGE("stat /data");

    return false;
  }

  struct hide_state state = { .data_dev = data.st_dev };

  /* INFO: The safe variant, as everywhere else in the loader: reading this
            process's own maps directly would leave a fresh access time on the
            file for the application to find. */
  if (!scan_maps_safe("self", collect_one_map, &state)) {
    LOGE("Failed to read the maps of this process");

    /* INFO: The visitor can have collected entries, and their paths, before the
              stream failed. */
    free_hide_state(&state);

    return false;
  }

  /* INFO: Nothing is hidden until the stream has closed and the child reading
            the maps is gone: the entries above were collected from a table
            that was still whole, and acting on them now cannot race the
            reader that produced them. */
  size_t maps = 0;
#ifndef NDEBUG
  size_t bytes = 0;
#endif

  for (size_t i = 0; i < state.count; i++) {
    struct hide_target *target = &state.targets[i];

    if (hide_map(target)) {
      maps++;
#ifndef NDEBUG
      bytes += target->size;
#endif
    }
  }

  free_hide_state(&state);

  /* INFO: The descriptor is scaffolding, not part of the hiding. Every copy
            was mmap'd MAP_SHARED from it and then moved into place, so each
            replaced range holds its own reference to the memfd's file and the
            maps line keeps naming /memfd:jit-zygote-cache after the fd is
            gone - closing it changes nothing an on-device scan can see.

            Leaving it open, on the other hand, is fatal in an app zygote.
            Those processes fork their sandboxed children through the zygote
            descriptor machinery (ForkCommon -> FileDescriptorTable::Restat),
            which walks /proc/self/fd and rejects any descriptor whose symlink
            is not on Android's allowlist. A memfd named jit-zygote-cache is
            not on it - only /memfd:/boot-image-methods.art is - so the fork
            aborts with "Not allowlisted (N): /memfd:jit-zygote-cache (deleted)"
            and the browser that owns that zygote ends up with no network. The
            fd is closed before the process ever reaches that fork. */
  if (hide_memfd != -1) {
    close(hide_memfd);
    hide_memfd = -1;
    hide_memfd_sealed = true;
  }

  if (maps > 0) LOGD("Hid %zu module map(s), %zu KiB", maps, bytes / 1024);

  /* INFO: Recorded whether or not anything was found. What the later pass needs
            to know is that this process has had its pass - and a process with
            nothing to hide is exactly the one that must not pay for reading the
            whole table a second time to learn the same thing. */
  module_maps_were_hidden = true;

  return true;
}
