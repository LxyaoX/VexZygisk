#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <limits.h>

#include <linux/un.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>

#include "logging.h"
#include "misc.h"
#include "socket_utils.h"

#include "daemon.h"

/* Bounds how long a request may block on the daemon once connected. A stalled
         or overloaded daemon would otherwise leave the caller - a zygote child
         mid-specialize - hung forever on read(), since a plain blocking socket
         has no deadline of its own. Cleared again wherever the socket stops
         being ours: the companion protocols belong to the modules, and they
         may legitimately block far longer than this budget. */
#define REZYGISKD_IO_TIMEOUT_SEC 3

/* INFO: The ceiling on any list length read off the wire. No real install
         carries more modules than this, and a count beyond it is either a
         corrupt length field or something pretending to be one - both are
         refused before a single entry is read, because reading thousands of
         strings against the 3 s budget below would stall a fork for no
         reason a real daemon would give it. */
#define REZYGISKD_MODULES_MAX 4096

static void set_socket_timeout(int fd, long seconds) {
  struct timeval tv = {
    .tv_sec = seconds,
    .tv_usec = 0
  };

  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int rezygiskd_connect(uint8_t retry, uint32_t retry_delay_us) {
  struct sockaddr_un addr = {
    .sun_family = AF_UNIX,
    .sun_path = { 0 }
  };
  /*
    INFO: Application must assume that sun_path can hold _POSIX_PATH_MAX characters.

    Sources:
     - https://pubs.opengroup.org/onlinepubs/009696699/basedefs/sys/un.h.html
  */
  _Static_assert(sizeof(ZYGISK_CP_SOCKET) <= sizeof(addr.sun_path),
                 "the daemon socket path no longer fits sun_path");

  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", ZYGISK_CP_SOCKET);

  for (uint8_t attempt = 0; attempt <= retry; attempt++) {
    int fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd == -1) {
      PLOGE("socket");

      return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != -1) {
      set_socket_timeout(fd, REZYGISKD_IO_TIMEOUT_SEC);

      return fd;
    }

    PLOGE("connect (attempt %d of %d)", attempt + 1, retry + 1);

    close(fd);

    /* INFO: Waiting is pointless once there is no attempt left to make. */
    if (attempt == retry) break;

    usleep(retry_delay_us);
  }

  return -1;
}

/* INFO: Logs the failed exchange, closes the daemon socket and bails out. */
#define safe_check(fn, what, ret_type)              \
  if (fn == -1) {                                   \
    LOGE("Failed to " what " with VexZygiskd");     \
                                                    \
    close(fd);                                      \
                                                    \
    ret_type;                                       \
  }

#define safe_write(fn, name, ret_type) safe_check(fn, "write " name, ret_type)
#define safe_read(fn, name, ret_type)  safe_check(fn, "read " name, ret_type)

bool rezygiskd_zygote_injected(void) {
  int fd = rezygiskd_connect(5, REZYGISKD_RETRY_DELAY_US);
  if (fd == -1) return false;

  safe_write(write_uint8_t(fd, (uint8_t)ZygoteInjected), "ZygoteInjected action", return false);

  close(fd);

  return true;
}

uint32_t rezygiskd_get_process_flags(uid_t uid, const char *const process) {
  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
  if (fd == -1) return 0;

  /* The action, the uid and the name leave in one writev instead of three
     writes: this runs in a zygote child on its way to its first frame, once per
     launch, and the daemon reads the same fields back - a stream socket carries
     no message boundaries.

     A short return drops the connection, as a failed write did. The socket
     carries SO_SNDTIMEO, so it means the daemon stopped reading. */
  uint8_t action = (uint8_t)GetProcessFlags;
  uint32_t uid_value = (uint32_t)uid;
  /* INFO: The length rides the wire as uint32_t like every other length in
            the protocol - see write_string in socket_protocol.h. */
  uint32_t name_len = (uint32_t)strlen(process);

  struct iovec request[4] = {
    { .iov_base = &action, .iov_len = sizeof(action) },
    { .iov_base = &uid_value, .iov_len = sizeof(uid_value) },
    { .iov_base = &name_len, .iov_len = sizeof(name_len) },
    { .iov_base = (void *)process, .iov_len = name_len }
  };

  const size_t total = sizeof(action) + sizeof(uid_value) + sizeof(name_len) + name_len;

  if (writev(fd, request, 4) != (ssize_t)total) {
    LOGE("Failed to write GetProcessFlags with VexZygiskd");

    close(fd);

    return 0;
  }

  uint32_t res = 0;
  safe_read(read_uint32_t(fd, &res), "process flags", return 0);

  close(fd);

  return res;
}

/* INFO: The display name of one module, from its own module.prop.

         The path is built here because the name it is built from arrived over a
         socket, so its length is not this process's to assume: a name that does
         not fit is refused rather than truncated, since a truncated path is
         still a valid-looking one and the fopen below would report "no such
         file" for a path nobody ever asked for.

         Returns a strdup'ed name, or NULL with the reason already logged. */
static char *read_module_prop_name(const char *module_name) {
  static const char kNameTag[] = "name=";
  const size_t tag_len = sizeof(kNameTag) - 1;

  char module_path[PATH_MAX];
  int written = snprintf(module_path, sizeof(module_path), "/data/adb/modules/%s/module.prop", module_name);

  if (written < 0 || (size_t)written >= sizeof(module_path)) {
    LOGE("module name is too long for a prop path (%d bytes)", written);

    return NULL;
  }

  FILE *module_prop = fopen(module_path, "r");
  if (module_prop == NULL) {
    PLOGE("failed to open module prop file %s", module_path);

    return NULL;
  }

  char *name = NULL;
  char line[1024];

  while (fgets(line, sizeof(line), module_prop) != NULL) {
    if (strncmp(line, kNameTag, tag_len) != 0) continue;

    size_t value_len = strlen(line + tag_len);

    /* INFO: The newline has to be there: it is what says the line was read in
              full, and the name is the text before it. */
    if (value_len == 0 || line[value_len + tag_len - 1] != '\n') {
      LOGE("Invalid module name in %s", module_path);

      break;
    }

    name = strndup(line + tag_len, value_len - 1);
    if (name == NULL) PLOGE("allocate memory for module name from %s", module_path);

    break;
  }

  /* INFO: LOGE and not PLOGE: this is the routine answer for a prop file
            with no name= line, and errno says nothing about it. */
  if (name == NULL) LOGE("failed to read module name from %s", module_path);

  fclose(module_prop);

  return name;
}

void rezygiskd_get_info(struct rezygisk_info *info) {
  /* INFO: The whole struct is zeroed before anything touches it: an exchange
            that fails halfway used to leave the caller's `modules` pointer
            uninitialized next to a live `running` flag, and freeing that is
            how a routine timeout turned into a crash. Zeroed, a failure is
            "not running", with nothing dangling behind it. */
  memset(info, 0, sizeof(*info));

  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
  if (fd == -1) return;

  info->running = true;

  safe_write(write_uint8_t(fd, (uint8_t)GetInfo), "GetInfo action", goto fail);

  /* INFO: The flags word is consumed to stay in step with the protocol; the
            daemon always sets the bit of the root solution it was built for,
            which this flavour is built to match. */
  uint32_t flags = 0;
  safe_read(read_uint32_t(fd, &flags), "info flags", goto fail);

#ifdef ROOT_IMPL_APATCH
  info->root_impl = ROOT_APATCH;
#else
  info->root_impl = ROOT_KERNELSU;
#endif

  uint32_t daemon_pid = 0;
  safe_read(read_uint32_t(fd, &daemon_pid), "pid", goto fail);

  info->pid = (pid_t)daemon_pid;

  size_t modules_count = 0;
  safe_read(read_size_t(fd, &modules_count), "modules count", goto fail);

  if (modules_count == 0) {
    close(fd);

    return;
  }

  /* INFO: The count arrives over the socket, so it is bounded before it is
            believed: an absurd one cannot be allocated, but it could still be
            read one string at a time against this socket's 3 s budget, which
            stalls a zygote child mid-specialize for no reason a real daemon
            would ever give it. */
  if (modules_count > REZYGISKD_MODULES_MAX) {
    LOGE("module count %zu exceeds the protocol bound", modules_count);

    goto fail;
  }

  /* INFO: calloc validates the multiplication for us; calloc refuses a
            wrapped count * sizeof(char *) and returns NULL. */
  info->modules.modules = (char **)calloc(modules_count, sizeof(char *));
  if (!info->modules.modules) {
    PLOGE("allocating modules name memory");

    goto fail;
  }
  info->modules.modules_count = modules_count;

  /* INFO: The list is handed back as far as it was read on every failure
            below: the count says how many entries exist, and the ones that were
            never reached are still the calloc'ed NULLs, so the caller can free
            the list and report a daemon that answered with less than it said. */
  for (size_t i = 0; i < info->modules.modules_count; i++) {
    char *module_name = read_string(fd);
    if (module_name == NULL) {
      PLOGE("reading module name");

      info->modules.modules_count = i;
      free_rezygisk_info(info);

      break;
    }

    info->modules.modules[i] = read_module_prop_name(module_name);

    free(module_name);

    if (info->modules.modules[i] == NULL) {
      info->modules.modules_count = i;
      free_rezygisk_info(info);

      break;
    }
  }

  close(fd);

  return;

  fail:
    info->running = false;

    close(fd);
}

void free_rezygisk_info(struct rezygisk_info *info) {
  free_modules(&info->modules);
}

bool rezygiskd_read_modules(struct zygisk_modules *modules) {
  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
  if (fd == -1) return false;

  safe_write(write_uint8_t(fd, (uint8_t)ReadModules), "ReadModules action", return false);

  size_t len = 0;
  safe_read(read_size_t(fd, &len), "modules count", return false);

  if (len > REZYGISKD_MODULES_MAX) {
    LOGE("modules count %zu exceeds the protocol bound", len);

    close(fd);

    return false;
  }

  /* INFO: calloc also validates the multiplication, so a corrupt count from
            the socket cannot overflow into an undersized allocation. */
  modules->modules = calloc(len, sizeof(char *));
  if (!modules->modules) {
    PLOGE("allocating modules name memory");

    close(fd);

    return false;
  }
  modules->modules_count = len;

  for (size_t i = 0; i < len; i++) {
    char *lib_path = read_string(fd);
    if (!lib_path) {
      PLOGE("reading module lib_path");

      modules->modules_count = i;
      free_modules(modules);

      close(fd);

      return false;
    }

    modules->modules[i] = lib_path;
  }

  close(fd);

  return true;
}

void free_modules(struct zygisk_modules *modules) {
  for (size_t i = 0; i < modules->modules_count; i++) {
    free(modules->modules[i]);
  }

  free(modules->modules);
  modules->modules = NULL;
  modules->modules_count = 0;
}

int rezygiskd_connect_companion(size_t index) {
  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
  if (fd == -1) return -1;

  safe_write(write_uint8_t(fd, (uint8_t)RequestCompanionSocket), "RequestCompanionSocket action", return -1);
  safe_write(write_size_t(fd, index), "companion index", return -1);

  uint8_t res = 0;
  safe_read(read_uint8_t(fd, &res), "companion socket result", return -1);

  if (res == 1) {
    /* INFO: Past this point the same socket is the module's companion
              channel, and the module's protocol may block far longer than
              our daemon handshake budget - hand it over unconstrained. */
    set_socket_timeout(fd, 0);

    return fd;
  } else {
    close(fd);

    return -1;
  }
}

int rezygiskd_get_module_dir(size_t index) {
  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
  if (fd == -1) return -1;

  safe_write(write_uint8_t(fd, (uint8_t)GetModuleDir), "GetModuleDir action", return -1);
  safe_write(write_size_t(fd, index), "module index", return -1);

  int dirfd = read_fd(fd);

  close(fd);

  return dirfd;
}

void rezygiskd_zygote_restart(void) {
  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
  if (fd == -1) return;

  safe_write(write_uint8_t(fd, (uint8_t)ZygoteRestart), "ZygoteRestart action", return);

  close(fd);
}

bool rezygiskd_update_mns(enum mount_namespace_state nms_state, char *buf, size_t buf_size) {
  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
  if (fd == -1) return false;

  safe_write(write_uint8_t(fd, (uint8_t)UpdateMountNamespace), "UpdateMountNamespace action", return false);
  /* The raw syscall: the caller may be a raw fork whose bionic pid cache still
     describes the parent. */
  safe_write(write_uint32_t(fd, (uint32_t)syscall(__NR_getpid)), "pid", return false);
  safe_write(write_uint8_t(fd, (uint8_t)nms_state), "mount namespace state", return false);

  uint32_t target_pid = 0;
  safe_read(read_uint32_t(fd, &target_pid), "target pid", return false);

  uint32_t target_fd = 0;
  safe_read(read_uint32_t(fd, &target_fd), "target fd", return false);

  if (target_fd == 0) {
    LOGE("Failed to get target fd");

    close(fd);

    return false;
  }

  int written = snprintf(buf, buf_size, "/proc/%u/fd/%u", target_pid, target_fd);
  if (written < 0 || (size_t)written >= buf_size) {
    LOGE("the target fd path does not fit the caller's buffer");

    close(fd);

    return false;
  }

  close(fd);

  return true;
}

bool rezygiskd_remove_module(size_t index) {
  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
  if (fd == -1) return false;

  safe_write(write_uint8_t(fd, (uint8_t)RemoveModule), "RemoveModule action", return false);
  safe_write(write_size_t(fd, index), "module index", return false);

  uint8_t res = 0;
  safe_read(read_uint8_t(fd, &res), "remove module result", return false);

  close(fd);

  return res == 1;
}

#undef safe_read
#undef safe_write
