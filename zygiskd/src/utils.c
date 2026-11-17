#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <fcntl.h>
#include <poll.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>

#include <linux/limits.h>
#include <sched.h>
#include <unistd.h>

#include "root_impl/common.h"

/* INFO: The names that make a mount a root trace: the very table the loader's
         revert uses, so a clean namespace and a reverted process always drop
         the same set. */
#include "root_mounts.h"

#include "utils.h"

bool switch_mount_namespace(pid_t pid) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d/ns/mnt", pid);

  int nsfd = open(path, O_RDONLY | O_CLOEXEC);
  if (nsfd == -1) {
    LOGE("Failed to open nsfd: %s", strerror(errno));

    return false;
  }

  if (setns(nsfd, CLONE_NEWNS) == -1) {
    LOGE("Failed to setns: %s", strerror(errno));

    close(nsfd);

    return false;
  }

  close(nsfd);

  return true;
}

static bool write_sockcreate(const char *restrict path, const char *restrict context) {
  FILE *sockcreate = fopen(path, "w");
  if (sockcreate == NULL) {
    LOGE("Failed to open %s with %d: %s", path, errno, strerror(errno));

    return false;
  }

  if (fwrite(context, 1, strlen(context), sockcreate) != strlen(context)) {
    LOGE("Failed to write to %s with %d: %s", path, errno, strerror(errno));

    fclose(sockcreate);

    return false;
  }

  fclose(sockcreate);

  return true;
}

void set_socket_create_context(const char *restrict context) {
  if (write_sockcreate("/proc/thread-self/attr/sockcreate", context)) return;

  /* INFO: thread-self can fail on very old kernels, so fall back to the
            explicit task directory of this thread. */
  char path[PATH_MAX];
  snprintf(path, PATH_MAX, "/proc/self/task/%d/attr/sockcreate", gettid());

  write_sockcreate(path, context);
}

static bool get_current_attr(char *restrict output, size_t size) {
  /* INFO: The caller writes a terminator at output[ret], so a zero size would
            make `size - 1` wrap to SIZE_MAX and let fread loose past the
            buffer. */
  if (size == 0) return false;

  FILE *current = fopen("/proc/self/attr/current", "r");
  if (current == NULL) {
    LOGE("fopen: %s", strerror(errno));

    return false;
  }

  size_t ret = fread(output, 1, size - 1, current);
  if (ferror(current)) {
    LOGE("fread: %s", strerror(errno));

    fclose(current);

    return false;
  }

  output[ret] = '\0';

  fclose(current);

  return true;
}

void unix_datagram_sendto(const char *restrict path, const void *restrict buf, size_t len) {
  char current_attr[PATH_MAX];
  if (!get_current_attr(current_attr, sizeof(current_attr))) {
    LOGE("Failed to get current attribute");

    return;
  }

  set_socket_create_context(current_attr);

  struct sockaddr_un addr = {
    .sun_family = AF_UNIX
  };
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

  int socket_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (socket_fd == -1) {
    LOGE("socket: %s", strerror(errno));

    goto restore;
  }

  if (connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    LOGE("connect: %s", strerror(errno));

    close(socket_fd);

    goto restore;
  }

  /* INFO: MSG_DONTWAIT keeps a wedged monitor from blocking the daemon in
            send once its receive buffer fills: the status update is dropped
            instead of stalling every zygote fork behind the request. The
            datagram either lands on an alive socket or the loss is logged. */
  if (send(socket_fd, buf, len, MSG_DONTWAIT) == -1) {
    LOGE("send: %s", strerror(errno));

    close(socket_fd);

    goto restore;
  }

  close(socket_fd);

  restore:
    set_socket_create_context("u:r:zygote:s0");
}

int chcon(const char *restrict path, const char *context) {
  return lsetxattr(path, "security.selinux", context, strlen(context) + 1, 0);
}

int unix_listener_from_path(const char *restrict path) {
  if (remove(path) == -1 && errno != ENOENT) {
    LOGE("remove: %s", strerror(errno));

    return -1;
  }

  int socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (socket_fd == -1) {
    LOGE("socket: %s", strerror(errno));

    return -1;
  }

  struct sockaddr_un addr = {
    .sun_family = AF_UNIX
  };
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

  if (bind(socket_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1) {
    LOGE("bind: %s", strerror(errno));

    close(socket_fd);

    return -1;
  }

  /* INFO: A backlog of 2 dropped connections whenever several zygote forks
             connected at once; the loader retries once at 100 ms, so a drop
             cost a whole inject attempt. */
  if (listen(socket_fd, 16) == -1) {
    LOGE("listen: %s", strerror(errno));

    close(socket_fd);

    return -1;
  }

  if (chcon(path, "u:object_r:zygisk_file:s0") == -1)
    LOGW("chcon (non-fatal): %s", strerror(errno));

  return socket_fd;
}

/* INFO: memfd_create() only reaches bionic from API 30, while common.mk builds
         against a much older one, so the syscall is issued directly. */
#ifndef MFD_CLOEXEC
  #define MFD_CLOEXEC 0x0001U
#endif

/* INFO: Sharing a staged memfd is only safe once nobody can rewrite it:
         F_ADD_SEALS (Linux 3.17+) makes the pages immutable for every
         holder, so a receiver cannot map it writable and poison the loads
         of the processes that come after it. Guarded so the file builds
         against older headers too. */
#ifndef MFD_ALLOW_SEALING
  #define MFD_ALLOW_SEALING 0x0008U
#endif
#ifndef F_ADD_SEALS
  #define F_ADD_SEALS 1033
#endif
#ifndef F_SEAL_SHRINK
  #define F_SEAL_SHRINK 0x0002U
  #define F_SEAL_GROW 0x0004U
  #define F_SEAL_WRITE 0x0008U
#endif

/* INFO: One staged library: an immutable memfd copy keyed by the source
         file's identity. ReadZnModules resolves matching modules for every
         fork, and restaging a multi-megabyte library each time is the most
         expensive thing the daemon does on that path; with the seal in
         place the same memfd is handed out repeatedly at descriptor-dup
         cost. Entries live for the daemon's lifetime; a module update
         lands on a new identity and is restaged over its slot. */
struct staged_library {
  char *path;
  struct stat st;
  int mem_fd;
};

#define STAGED_LIBRARY_MAX 16

static struct staged_library staged_libraries[STAGED_LIBRARY_MAX];

/* INFO: Fills a fresh memfd with the contents of file_fd, optionally
         sealing it. Returns -1 when the staging or the seal fails. */
static int stage_library_bytes(int file_fd, const char *restrict path, bool seal) {
  /* INFO: path names the failures; under NDEBUG the logs vanish and the
            parameter would read as unused. */
  (void) path;

  int mem_fd = (int)syscall(__NR_memfd_create, "zn-module",
                            MFD_CLOEXEC | (seal ? MFD_ALLOW_SEALING : 0));
  if (mem_fd == -1) return -1;

  /* INFO: sendfile moves the bytes inside the kernel — the source is a
            regular file and the memfd a tmpfs one — which halves the syscall
            count for multi-megabyte libraries; the byte loop stays as the
            fallback for filesystem pairs that refuse it, restarting the copy
            from scratch since sendfile may have moved part of the file. */
  bool copied = true;
  off_t offset = 0;

  for (;;) {
    ssize_t sent = sendfile(mem_fd, file_fd, &offset, 1 << 20);

    if (sent == 0) break;

    if (sent < 0) {
      if (errno == EINTR) continue;

      if (ftruncate(mem_fd, 0) == -1 || lseek(mem_fd, 0, SEEK_SET) == -1) {
        copied = false;

        break;
      }

      char buffer[65536];

      for (;;) {
        ssize_t got = read(file_fd, buffer, sizeof(buffer));
        if (got == -1) {
          if (errno == EINTR) continue;

          LOGE("Failed reading \"%s\": %s", path, strerror(errno));

          copied = false;

          break;
        }

        if (got == 0) break;

        if (write_loop(mem_fd, buffer, (size_t)got) != got) {
          LOGE("Failed filling the memfd of \"%s\"", path);

          copied = false;

          break;
        }
      }

      break;
    }
  }

  if (!copied) {
    close(mem_fd);

    return -1;
  }

  /* INFO: No log on seal failure on purpose: on a kernel without sealing
            this fires for every staged library, and the INFO comment above
            already documents the per-call fallback. */
  if (seal && fcntl(mem_fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_WRITE) == -1) {
    close(mem_fd);

    return -1;
  }

  return mem_fd;
}

/* INFO: Hands a library over as a memfd instead of a descriptor of the file
         itself, which is what lets an unprivileged target load it at all.

         Reopening /proc/self/fd skips the permissions of every directory
         leading to the file, /data/adb among them, but the file then still
         carries its own mode and its SELinux label, and a target that is not
         root is usually allowed to touch neither. A memfd is created here, so
         it is owned by this daemon and labelled after its domain.

         On success *shared says who owns the descriptor: true means it is a
         daemon-cached, sealed copy that later requests reuse and the caller
         must not close; false means a per-call copy (kernels without
         sealing, or every slot taken) that the caller closes right after the
         handover. */
int create_library_fd(const char *restrict path, bool *shared) {
  *shared = false;

  struct stat st;
  if (stat(path, &st) == -1) {
    LOGE("Failed stating \"%s\": %s", path, strerror(errno));

    return -1;
  }

  struct staged_library *free_slot = NULL;

  for (size_t i = 0; i < STAGED_LIBRARY_MAX; i++) {
    struct staged_library *slot = &staged_libraries[i];

    if (slot->path == NULL) {
      if (free_slot == NULL) free_slot = slot;

      continue;
    }

    if (strcmp(slot->path, path) != 0) continue;

    if (stat_identity_same(&slot->st, &st)) {
      *shared = true;

      return slot->mem_fd;
    }

    /* INFO: The module was updated: drop the stale copy and restage. */
    close(slot->mem_fd);
    free(slot->path);
    slot->path = NULL;
    slot->mem_fd = -1;

    if (free_slot == NULL) free_slot = slot;

    break;
  }

  int file_fd = open(path, O_RDONLY | O_CLOEXEC);
  if (file_fd == -1) {
    LOGE("Failed opening \"%s\": %s", path, strerror(errno));

    return -1;
  }

  /* INFO: The identity the cache records is the one the bytes actually came
            from, not the one the path had a moment earlier: a module update
            by rename can swap the file between the stat above and this open,
            and a cache keyed on the old identity would keep serving the new
            bytes as the old version forever - the next stat still matches,
            so nothing would ever restage. */
  if (fstat(file_fd, &st) == -1) {
    LOGE("Failed stating the opened \"%s\": %s", path, strerror(errno));

    close(file_fd);

    return -1;
  }

  int mem_fd = stage_library_bytes(file_fd, path, true);
  close(file_fd);

  if (mem_fd == -1) {
    /* INFO: Without sealing a shared memfd could be remapped writable by
              whoever receives it and poison every later loader, so kernels
              without sealing keep the pre-cache behaviour: a fresh per-call
              copy the caller closes after the handover. */
    file_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (file_fd == -1) return -1;

    mem_fd = stage_library_bytes(file_fd, path, false);
    close(file_fd);

    return mem_fd;
  }

  if (free_slot != NULL) {
    free_slot->path = strdup(path);

    if (free_slot->path != NULL) {
      free_slot->st = st;
      free_slot->mem_fd = mem_fd;
      *shared = true;
    }
    /* INFO: Out of memory for the bookkeeping: the sealed copy is still
              handed out, just untracked and closed by the caller. */
  }

  return mem_fd;
}



ssize_t read_string(int fd, char *restrict buf, size_t buf_size) {
  uint32_t str_len = 0;
  ssize_t read_bytes = read_loop(fd, &str_len, sizeof(str_len));
  if (read_bytes != (ssize_t)sizeof(str_len)) {
    LOGE("Failed to read string length: Not all bytes were read (%zd != %zu).", read_bytes, sizeof(str_len));

    return -1;
  }

  if (buf_size == 0 || str_len > buf_size - 1) {
    LOGE("Failed to read string: Buffer is too small (%u > %zu - 1).", str_len, buf_size);

    return -1;
  }

  read_bytes = read_loop(fd, buf, str_len);
  if (read_bytes != (ssize_t)str_len) {
    LOGE("Failed to read string: Promised bytes doesn't exist (%zd != %u).", read_bytes, str_len);

    return -1;
  }

  buf[str_len] = '\0';

  return read_bytes;
}

bool check_unix_socket(int fd, bool block) {
  struct pollfd pfd = {
    .fd = fd,
    .events = POLLIN,
    .revents = 0
  };

  int timeout = block ? -1 : 0;
  if (poll(&pfd, 1, timeout) == -1) {
    LOGE("poll: %s", strerror(errno));

    return false;
  }

  return pfd.revents & ~POLLIN ? false : true;
}

void stringify_root_impl_name(struct root_impl impl, char *restrict output) {
#ifdef ROOT_IMPL_APATCH
  switch (impl.impl) {
    case RootAPatch: {
      strcpy(output, "APatch");

      break;
    }
  }
#else
  switch (impl.impl) {
    case RootKernelSU: {
      strcpy(output, "KernelSU");

      break;
    }
  }
#endif
}

/* INFO: The fields of one mountinfo line are `struct mount_entry` in
         root_mounts.h, shared with the loader's walker. Only the mount point
         and the source and root it matches against are read here; the id the
         struct also carries is the loader's, which orders the revert by it. */
struct mountinfos {
  struct mount_entry *mounts;
  size_t length;
};

void free_mounts(struct mountinfos *restrict mounts) {
  for (size_t i = 0; i < mounts->length; i++) {
    free(mounts->mounts[i].root);
    free(mounts->mounts[i].target);
    free(mounts->mounts[i].source);
  }

  free(mounts->mounts);
}

/* INFO: One mountinfo line. The split and the field reads are shared with the
         loader's walker (root_mounts.h); this side only copies what it keeps,
         and skips a line that is not a mount without a word about it - a
         pseudo-filesystem with no source is routine in this file. */
static bool mountinfo_parse_line(char *line, struct mount_entry *out) {
  unsigned int id = 0;
  char root[MOUNT_FIELD_MAX], target[MOUNT_FIELD_MAX];
  char source[MOUNT_FIELD_MAX], type[MOUNT_TYPE_MAX];

  if (!mount_entry_split(line, &id, root, target, type, source)) return false;

  out->id = id;
  out->root = strdup(root);
  out->target = strdup(target);
  out->source = strdup(source);

  if (out->root == NULL || out->target == NULL || out->source == NULL) {
    free(out->root);
    free(out->target);
    free(out->source);

    out->root = NULL;
    out->target = NULL;
    out->source = NULL;

    return false;
  }

  return true;
}

bool parse_mountinfo(const char *restrict pid, struct mountinfos *restrict mounts) {
  char path[PATH_MAX];
  snprintf(path, PATH_MAX, "/proc/%s/mountinfo", pid);

  FILE *mountinfo = fopen(path, "re");
  if (mountinfo == NULL) {
    LOGE("fopen: %s", strerror(errno));

    return false;
  }

  char *line = NULL;
  size_t line_capacity = 0;
  size_t i = 0;

  mounts->mounts = NULL;
  mounts->length = 0;

  while (getline(&line, &line_capacity, mountinfo) > 0) {
    size_t length = strlen(line);
    while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) line[--length] = '\0';

    struct mount_entry *tmp_mounts = (struct mount_entry *)realloc(mounts->mounts, (i + 1) * sizeof(struct mount_entry));
    if (!tmp_mounts) {
      LOGE("Failed to allocate memory for mounts->mounts");

      goto cleanup_mount_allocs;
    }
    mounts->mounts = tmp_mounts;

    struct mount_entry *mount = &mounts->mounts[i];

    if (!mountinfo_parse_line(line, mount)) {
      /* INFO: Lines without a source (pseudo-filesystems) are routine here,
                so a skipped line is not worth a log entry. The slot is left
                to be reused by the next line; the length only counts fully
                parsed entries, so consumers never see NULL fields. */
      continue;
    }

    mounts->length = ++i;
  }

  free(line);
  fclose(mountinfo);

  return true;

  cleanup_mount_allocs:
    /* INFO: The length counts every allocated entry, so free_mounts
             releases exactly what was built. */
    free_mounts(mounts);
    free(line);
    fclose(mountinfo);

    return false;
}

static const char *find_module_loop_source(const struct mountinfos *all) {
  const char *source = mount_find_loop_source(all->mounts, all->length);
  if (source == NULL) return NULL;

  LOGD("Detected the KernelSU module loop source: %s", source);

  return source;
}

/* INFO: Detaches the root traces rather than unmounting them: every removal
         below is umount2(MNT_DETACH), so the filesystem instances stay alive
         for whoever already holds a reference and only this namespace's mount
         tree loses them. The name says so now - "umount" promised a reach the
         code deliberately does not have. */
static bool detach_root_mounts(void) {
  /* INFO: This runs in a child that already setns'ed into the target pid's
            mount namespace, so "self" here is the namespace to clean. */
  struct mountinfos mounts;
  if (!parse_mountinfo("self", &mounts)) {
    LOGE("Failed to parse mountinfo");

    return false;
  }

  const char *source_name = kRootSources[0];

  /* INFO: Only the logs read it; keep the variable for debug builds. */
  (void) source_name;

  LOGI("[%s] Unmounting root", source_name);

  char **targets_to_unmount = NULL;
  size_t num_targets = 0;

  /* INFO: loop_source borrows a string owned by `mounts`; it is only read
           across the selection loop below, which runs before free_mounts. */
  const char *loop_source = find_module_loop_source(&mounts);

  for (size_t i = 0; i < mounts.length; i++) {
    struct mount_entry mount = mounts.mounts[i];

    /* INFO: The same question the loader asks while reverting, through the same
              function. It used to be spelled out here as four conditions in a
              different order, which is precisely the drift that makes one
              walker drop a mount the other keeps - a process that is half
              hidden. */
    if (!mount_carries_root_trace(mount.root, mount.target, mount.source, loop_source)) continue;

    char **tmp_targets = realloc(targets_to_unmount, (num_targets + 1) * sizeof(char*));
    if (tmp_targets == NULL) {
      LOGE("[%s] Failed to allocate memory for targets_to_unmount", source_name);

      free(targets_to_unmount);

      free_mounts(&mounts);

      return false;
    }
    targets_to_unmount = tmp_targets;

    num_targets++;

    targets_to_unmount[num_targets - 1] = mount.target;
  }

  for (size_t i = num_targets; i > 0; i--) {
    const char *target = targets_to_unmount[i - 1];

    /* INFO: MNT_DETACH, for the same reason the loader reverts through it:
               detaching hides the mount from this namespace without tearing
               the filesystem instance down, so an overlay that a root solution
               named after itself can cover system paths and still leave the
               framework and provider resources that WebView resolves through
               them intact. A plain umount2(target, 0) does tear it down and
               leaves those lookups pointing at a path the process's own
               mountinfo still reports as overlaid. */
    if (umount2(target, MNT_DETACH) == -1) {
      LOGE("[%s] Failed to detach %s: %s", source_name, target, strerror(errno));

      continue;
    }

    LOGI("[%s] Detached %s", source_name, target);
  }

  free(targets_to_unmount);

  free_mounts(&mounts);

  return true;
}

/* INFO: The helper child: enters the target's mount namespace, forks a private
         copy of the tree, and strips the root traces out of it. That copy is
         what a denylisted process is switched into when the in-place revert
         could not be applied, and it is not optional - without it the umount
         would run against the target's own namespace and take the mounts out
         from under the process this exists to protect.

         Every failure writes the byte the parent waits for and falls to the
         same place, which is why they share a label instead of repeating the
         three lines. It never returns: both paths end in _exit. */
static void mns_helper_run(int pid, int socket_child) {
  if (switch_mount_namespace(pid) == false) {
    LOGE("Failed to switch mount namespace");

    if (write_uint8_t(socket_child, 0) == -1)
      LOGE("Failed to write to socket_child: %s", strerror(errno));

    goto finalize_mns_fork;
  }

  /* INFO: The helper forks a private copy of the mount tree and strips the
            root traces out of it. That copy is what a denylisted process is
            switched into when the in-place revert could not be applied.
            The copy is not optional: without it the umount below would run
            against the target's own namespace and strip the mounts out from
            under the process this is meant to protect. */
  if (unshare(CLONE_NEWNS) == -1) {
    LOGE("Failed to unshare the mount namespace: %s", strerror(errno));

    if (write_uint8_t(socket_child, 0) == -1)
      LOGE("Failed to write to socket_child: %s", strerror(errno));

    goto finalize_mns_fork;
  }

  if (!detach_root_mounts()) {
    LOGE("Failed to umount root");

    if (write_uint8_t(socket_child, 0) == -1)
      LOGE("Failed to write to socket_child: %s", strerror(errno));

    goto finalize_mns_fork;
  }

  if (write_uint8_t(socket_child, 1) == -1) {
    LOGE("Failed to write to socket_child: %s", strerror(errno));

    close(socket_child);

    _exit(1);
  }

  uint8_t has_opened = 0;
  if (read_uint8_t(socket_child, &has_opened) == -1)
    LOGE("Failed to read from socket_child: %s", strerror(errno));

  finalize_mns_fork:
    close(socket_child);

    _exit(0);
}

/* INFO: The parent side of the handshake, up to the namespace fd being ready.

         FAIL_MNS is defined here rather than above because both of the things it
         closes are parameters of this function. It reaps the helper on every way
         out, which is what keeps a long-lived daemon from collecting zombies.

         The fd itself is the caller's to keep: that is the cache, and it is the
         only part of this that outlives the call. */
static int mns_parent_collect(pid_t fork_pid, int socket_parent) {
  #define FAIL_MNS(message)                                    \
    do {                                                       \
      LOGE("%s: %s", message, strerror(errno));                \
                                                                 \
      close(socket_parent);                                    \
      waitpid(fork_pid, NULL, 0);                              \
                                                                 \
      return -1;                                               \
    } while (0)

  uint8_t has_succeeded = 0;
  if (read_uint8_t(socket_parent, &has_succeeded) == -1) FAIL_MNS("Failed to read from socket_parent");

  if (!has_succeeded) {
    LOGE("Failed to umount root");

    close(socket_parent);
    waitpid(fork_pid, NULL, 0);

    return -1;
  }

  char ns_path[PATH_MAX];
  snprintf(ns_path, PATH_MAX, "/proc/%d/ns/mnt", fork_pid);

  /* INFO: CLOEXEC only matters at exec time; the fd stays open in the daemon
            for the loader to reach through /proc, but never leaks into a
            companion spawned afterwards. */
  int ns_fd = open(ns_path, O_RDONLY | O_CLOEXEC);
  if (ns_fd == -1) FAIL_MNS("open");

  uint8_t opened_signal = 1;
  if (write_uint8_t(socket_parent, opened_signal) == -1) {
    close(ns_fd);
    FAIL_MNS("Failed to write to socket_parent");
  }

  if (close(socket_parent) == -1) {
    /* INFO: Deliberately not routed through FAIL_MNS: that macro closes
              socket_parent a second time, and a close() reporting EINTR has
              still closed the descriptor on Linux - the retry could land on
              whatever fd took the number. */
    LOGE("Failed to close socket_parent: %s", strerror(errno));

    close(ns_fd);
    waitpid(fork_pid, NULL, 0);

    return -1;
  }

  if (waitpid(fork_pid, NULL, 0) == -1) {
    LOGE("waitpid: %s", strerror(errno));

    close(ns_fd);

    return -1;
  }

  return ns_fd;

  #undef FAIL_MNS
}


int save_mns_fd(int pid) {
  /* INFO: Every denylisted process that falls back to the clean namespace asks
            for it, so it is cached for the daemon's lifetime instead of being
            forked per process. */
  static int clean_namespace_fd = -1;

  if (clean_namespace_fd != -1) return clean_namespace_fd;

  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == -1) {
    LOGE("socketpair: %s", strerror(errno));

    return -1;
  }

  int socket_parent = sockets[0];
  int socket_child = sockets[1];

  /* INFO: The handshake runs inside a request handler; a helper wedged on a
            strange /proc entry must not block the daemon for good. On a
            timeout the socket is closed, which makes the child's next write
            fail and lets it exit for the reap below.

            Two seconds rather than the exchange budget of three: the helper
            opens one descriptor and writes it back, which is milliseconds,
            and every denylisted process that has to wait behind it is a
            fork mid-specialize. */
  struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
  setsockopt(socket_parent, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(socket_parent, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  pid_t fork_pid = fork();
  if (fork_pid < 0) {
    LOGE("fork: %s", strerror(errno));

    close(socket_parent);
    close(socket_child);

    return -1;
  }

  if (fork_pid == 0) {
    close(socket_parent);

    mns_helper_run(pid, socket_child);
  }

  close(socket_child);

  int ns_fd = mns_parent_collect(fork_pid, socket_parent);
  if (ns_fd == -1) return -1;

  /* INFO: The helper is gone by now, but the namespace it named survives:
            the fd taken from /proc holds it for the daemon's lifetime. */
  clean_namespace_fd = ns_fd;

  return ns_fd;
}
