#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <linux/limits.h>
#include <unistd.h>

#include "constants.h"
#include "zygisk_paths.h"
#include "root_impl/common.h"
#include "utils.h"

/* INFO: The flag naming the root solution this daemon was built for. Only the
         corresponding bit is ever set; the loader matches on whichever root
         it is told about. */
#ifdef ROOT_IMPL_APATCH
  #define PROCESS_ROOT_IS_ACTIVE PROCESS_ROOT_IS_APATCH
#else
  #define PROCESS_ROOT_IS_ACTIVE PROCESS_ROOT_IS_KSU
#endif

struct Module {
  char *name;
  int lib_fd;
  int companion;
};

struct Context {
  struct Module *modules;
  size_t len;
};

#define ARCH_STR "arm64-v8a"

/* INFO: The paths inside a module's directory, built in one place. The daemon
         composes them in eight, and a suffix that changes on one side while
         another keeps the old spelling means a module is loaded from one path
         while its marker is probed for at a different one. Every caller passes
         a PATH_MAX buffer. */
static void module_dir_path(char *out, size_t size, const char *name) {
  snprintf(out, size, "%s/%s", ZYGISK_MODULES_DIR, name);
}

static void module_file_path(char *out, size_t size, const char *name, const char *leaf) {
  snprintf(out, size, "%s/%s/%s", ZYGISK_MODULES_DIR, name, leaf);
}

static void module_lib_path(char *out, size_t size, const char *name) {
  snprintf(out, size, "%s/%s/zygisk/%s.so", ZYGISK_MODULES_DIR, name, ARCH_STR);
}

/* INFO: One datagram's worth of the controller protocol, built field by
         field and sent whole.

         The controller socket is a datagram socket, and a datagram is the
         only unit it delivers indivisibly. The records this builds used to
         be sent one field per sendto, which put the message's atomicity at
         the mercy of the receiver's wakeup timing: a reader that woke
         between two fields read a half-record and then parsed the next
         datagram's first byte as a command. One datagram per record closes
         that by construction. */
#define CONTROLLER_DGRAM_MAX 4096

struct controller_dgram {
  uint8_t bytes[CONTROLLER_DGRAM_MAX];
  size_t len;
};

static bool controller_dgram_put_u8(struct controller_dgram *restrict dgram, uint8_t value) {
  if (dgram->len + sizeof(value) > sizeof(dgram->bytes)) return false;

  dgram->bytes[dgram->len] = value;
  dgram->len += sizeof(value);

  return true;
}

static bool controller_dgram_put_u32(struct controller_dgram *restrict dgram, uint32_t value) {
  if (dgram->len + sizeof(value) > sizeof(dgram->bytes)) return false;

  memcpy(&dgram->bytes[dgram->len], &value, sizeof(value));
  dgram->len += sizeof(value);

  return true;
}

static bool controller_dgram_put_bytes(struct controller_dgram *restrict dgram, const void *restrict data, size_t len) {
  if (len > sizeof(dgram->bytes) || dgram->len + len > sizeof(dgram->bytes)) return false;

  memcpy(&dgram->bytes[dgram->len], data, len);
  dgram->len += len;

  return true;
}

/* INFO: A length-prefixed string, the same framing the reader takes apart. */
static bool controller_dgram_put_string(struct controller_dgram *restrict dgram, const char *restrict str) {
  size_t len = strlen(str);

  return controller_dgram_put_u32(dgram, (uint32_t)len) && controller_dgram_put_bytes(dgram, str, len);
}

static void controller_dgram_send(const struct controller_dgram *restrict dgram) {
  unix_datagram_sendto(ZYGISK_CONTROLLER_SOCKET, dgram->bytes, dgram->len);
}

/* INFO: An entry that cannot be built whole is announced as an empty classic
         entry instead: the count the SET_INFO record promised has to be met
         with something the reader can walk, and a datagram that stops
         mid-field is exactly the desync the one-record-one-datagram rule
         exists to prevent. */
static void send_minimal_module_entry(void) {
  struct controller_dgram dgram = { .len = 0 };

  controller_dgram_put_u8(&dgram, DAEMON_MODULE_ENTRY);
  controller_dgram_put_string(&dgram, "");

  controller_dgram_send(&dgram);
}

/* INFO: A standard Zygisk module entry. */
static void send_module_info(const char *name) {
  struct controller_dgram dgram = { .len = 0 };

  if (!controller_dgram_put_u8(&dgram, DAEMON_MODULE_ENTRY) ||
      !controller_dgram_put_string(&dgram, name)) {
    LOGE("The module entry for \"%s\" does not fit one datagram", name);

    send_minimal_module_entry();

    return;
  }

  controller_dgram_send(&dgram);
}

/* INFO: Declared here because load_modules bails out through it, and it is
         defined further down where the rest of the context handling lives. */
static void free_modules(struct Context *restrict context);

static void load_modules(struct Context *restrict context) {
  context->len = 0;
  context->modules = NULL;

  DIR *dir = opendir(ZYGISK_MODULES_DIR);
  if (dir == NULL) {
    LOGE("Failed opening modules directory: %s.", ZYGISK_MODULES_DIR);

    return;
  }

  LOGI("Loading modules for architecture: " ARCH_STR);

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    /* INFO: Some filesystems (fuse, certain overlays) report DT_UNKNOWN, and
             skipping those would silently drop every module, so the type is
             only used to rule out what is definitely not a directory. */
    if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN) continue;
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, "rezygisk") == 0) continue;

    char *name = entry->d_name;

    char disabled[PATH_MAX];
    module_file_path(disabled, PATH_MAX, name, "disable");

    if (access(disabled, F_OK) == 0) continue;

    char so_path[PATH_MAX];
    module_lib_path(so_path, PATH_MAX, name);

    int lib_fd = open(so_path, O_RDONLY | O_CLOEXEC);
    if (lib_fd == -1) {
      LOGE("Failed loading module \"%s\"", name);

      continue;
    }

    struct Module *tmp_modules = realloc(context->modules, (context->len + 1) * sizeof(struct Module));
    if (tmp_modules == NULL) {
      LOGE("Failed reallocating memory for modules.");

      close(lib_fd);

      goto load_modules_fail;
    }
    context->modules = tmp_modules;

    context->modules[context->len].name = strdup(name);
    if (context->modules[context->len].name == NULL) {
      LOGE("Failed to strdup for the module \"%s\": %s", name, strerror(errno));

      close(lib_fd);

      goto load_modules_fail;
    }

    context->modules[context->len].lib_fd = lib_fd;
    context->modules[context->len].companion = -1;
    context->len++;
  }

  closedir(dir);

  return;

  load_modules_fail:
    free_modules(context);
    closedir(dir);
}

static void free_modules(struct Context *restrict context) {
  for (size_t i = 0; i < context->len; i++) {
    free(context->modules[i].name);
    if (context->modules[i].companion >= 0) close(context->modules[i].companion);
    if (context->modules[i].lib_fd >= 0) close(context->modules[i].lib_fd);
  }

  free(context->modules);
  context->modules = NULL;
  context->len = 0;
}

/* INFO: Every exchange the daemon takes part in is bound by this, client
           and companion sockets alike: a stuck peer must never stall the
           zygote forks waiting behind it.

           Three, because three is the whole budget the loader side gives any
           request it makes (REZYGISKD_IO_TIMEOUT_SEC in the loader's
           daemon.c): serving a client for longer than that only delays every
           fork queued behind it, for a caller that has already given up. */
#define DAEMON_EXCHANGE_TIMEOUT_SECS 3

/* Forks a process that runs "zygiskd <mode> <fd>" and hands it the child end
   of a socket pair, so the companion keeps the daemon's SELinux domain.
   Returns 0 with the parent end in *out_fd, or -1 on failure. */
static int exec_companion(char *restrict argv[], const char *restrict tag, const char *restrict mode, int *out_fd) {
  int sockets[2];
  /* INFO: CLOEXEC keeps every unrelated daemon descriptor (the listening
            socket, other companions' control sockets, accepted client fds)
            out of the freshly execed companion; the child end is explicitly
            un-CLOEXEC'ed below, which is what lets it survive the exec. */
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == -1) {
    LOGE("Failed creating the companion socket pair.");

    return -1;
  }

  int daemon_fd = sockets[0];
  int companion_fd = sockets[1];

  /* INFO: The handshake below runs inside a request handler: a companion
            wedged in its constructor would otherwise hang the daemon — and
            with it every later zygote fork — indefinitely. */
  struct timeval timeout = { .tv_sec = DAEMON_EXCHANGE_TIMEOUT_SECS, .tv_usec = 0 };
  setsockopt(daemon_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(daemon_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  pid_t pid = fork();
  if (pid < 0) {
    LOGE("Failed forking the companion: %s", strerror(errno));

    close(companion_fd);
    close(daemon_fd);

    return -1;
  }

  if (pid > 0) {
    close(companion_fd);

    int status = 0;

    /* INFO: A signal delivered while waiting would otherwise be read as a
              failed exit: status is still zeroed and WIFEXITED(0) happens to
              be true, so the daemon would carry on with a socket no companion
              is holding. */
    while (waitpid(pid, &status, 0) == -1) {
      if (errno != EINTR) {
        LOGE("Failed waiting for the companion intermediate process: %s", strerror(errno));

        close(daemon_fd);

        return -1;
      }
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      LOGE("Exited with status %d", status);

      close(daemon_fd);

      return -1;
    }

    *out_fd = daemon_fd;

    return 0;
  }

  close(daemon_fd);

  if (fcntl(companion_fd, F_SETFD, 0) == -1) {
    LOGE("Failed removing FD_CLOEXEC flag: %s", strerror(errno));

    close(companion_fd);

    /* INFO: _exit, not exit: this fork still carries the daemon's stdio
              buffers and atexit handlers, and running them here would flush
              the same output the parent is about to flush again. */
    _exit(1);
  }

  char *last = strrchr(argv[0], '/');

  char nice_name[256];
  snprintf(nice_name, sizeof(nice_name), "%s", last == NULL ? argv[0] : last + 1);

  char process_name[256];
  snprintf(process_name, sizeof(process_name), "%s-%s", nice_name, tag);

  char companion_fd_str[32];
  snprintf(companion_fd_str, sizeof(companion_fd_str), "%d", companion_fd);

  char mode_arg[32];
  snprintf(mode_arg, sizeof(mode_arg), "%s", mode);

  char *eargv[] = { process_name, mode_arg, companion_fd_str, NULL };

  /* INFO: The parent waitpids on this process, so it must not become the
            companion itself: fork once more and let the grandchild exec,
            orphaning the long-lived companion to init. The earlier
            non_blocking_execv hid this double fork behind a dead pipe. */
  pid_t inner_pid = fork();
  if (inner_pid == -1) {
    LOGE("Failed forking the companion child: %s", strerror(errno));

    close(companion_fd);

    _exit(1);
  }

  if (inner_pid == 0) {
    execv(ZYGISKD_BIN, eargv);

    LOGE("Failed executing the companion: %s", strerror(errno));

    close(companion_fd);

    _exit(1);
  }

  _exit(0);
}

/* Spawns the companion of a Zygisk module. The library is already open, its
   descriptor is simply handed over. Returns the control socket, -2 when the
   module has no companion entry at all, or -1 on failure. */
static int spawn_companion(char *restrict argv[], char *restrict name, int lib_fd) {
  int daemon_fd = -1;
  if (exec_companion(argv, name, "companion", &daemon_fd) == -1) return -1;

  if (write_string(daemon_fd, name) == -1) {
    LOGE("Failed writing module name.");

    close(daemon_fd);

    return -1;
  }

  if (write_fd(daemon_fd, lib_fd) == -1) {
    LOGE("Failed sending library fd.");

    close(daemon_fd);

    return -1;
  }

  uint8_t response = 0;
  if (read_uint8_t(daemon_fd, &response) <= 0) {
    LOGE("Failed reading companion response.");

    close(daemon_fd);

    return -1;
  }

  if (response == 0) {
    close(daemon_fd);

    return -2;
  }

  if (response != 1) {
    LOGE("Unexpected companion response %u", response);

    close(daemon_fd);

    return -1;
  }

  return daemon_fd;
}

static int create_daemon_socket(void) {
  set_socket_create_context("u:r:zygote:s0");

  return unix_listener_from_path(ZYGISK_CP_SOCKET);
}

/* INFO: Pushes the root implementation and the module list to the controller
         socket, which the monitor folds into the module description. Sent once
         at startup and again whenever the module list changes. */
static void send_daemon_info(const struct Context *restrict context) {
  struct root_impl impl;
  get_impl(&impl);

  char impl_name[LONGEST_ROOT_IMPL_NAME];
  stringify_root_impl_name(impl, impl_name);

  /* INFO: The count has to match what is actually sent below: tombstoned
            slots carry no name and are not announced, so the live module
            entries are counted first. */
  uint32_t modules_len = 0;
  for (size_t i = 0; i < context->len; i++) {
    if (context->modules[i].name != NULL) modules_len++;
  }

  /* INFO: The announcement is one datagram: header, root implementation,
            module count. The entries follow as one datagram each, so the
            reader never holds a record open across a wakeup. */
  struct controller_dgram dgram = { .len = 0 };

  if (!controller_dgram_put_u8(&dgram, DAEMON_SET_INFO) ||
      !controller_dgram_put_string(&dgram, impl_name) ||
      !controller_dgram_put_u32(&dgram, modules_len)) {
    LOGE("The daemon info announcement does not fit one datagram");

    return;
  }

  controller_dgram_send(&dgram);

  for (size_t i = 0; i < context->len; i++) {
    /* INFO: Tombstoned slots carry no name and are not announced. */
    if (context->modules[i].name == NULL) continue;

    send_module_info(context->modules[i].name);
  }
}

/* INFO: The ceiling of the reload snapshot: more modules than this are
           beyond any install this serves, and the reload keeps what it has
           rather than growing the stack further. */
#define RELOAD_SNAPSHOT_MAX 512

/* Re-reads the modules directory without moving a live index.

   A zygote that already read the list holds indices into context->modules, which
   is what the RemoveModule tombstone exists for; a rebuild-from-scratch threw
   that away. So the reload merges: gone modules are tombstoned where they sit,
   kept ones are refreshed (their library descriptor re-opened), new ones
   appended. */
static void reload_modules(struct Context *restrict context) {
  /* INFO: The directory is read into a snapshot first, so that "is this
            module still on disk" is answered against one instant of it. */
  char *names[RELOAD_SNAPSHOT_MAX];
  int lib_fds[RELOAD_SNAPSHOT_MAX];
  size_t snapshot_len = 0;

  DIR *dir = opendir(ZYGISK_MODULES_DIR);
  if (dir != NULL) {
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && snapshot_len < RELOAD_SNAPSHOT_MAX) {
      if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN) continue;
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, "rezygisk") == 0) continue;

      char disabled[PATH_MAX];
      module_file_path(disabled, PATH_MAX, entry->d_name, "disable");
      if (access(disabled, F_OK) == 0) continue;

      char so_path[PATH_MAX];
      module_lib_path(so_path, PATH_MAX, entry->d_name);

      int lib_fd = open(so_path, O_RDONLY | O_CLOEXEC);
      if (lib_fd == -1) continue;

      names[snapshot_len] = strdup(entry->d_name);
      if (names[snapshot_len] == NULL) {
        close(lib_fd);

        continue;
      }

      lib_fds[snapshot_len] = lib_fd;
      snapshot_len++;
    }

    closedir(dir);
  }

  /* INFO: Existing slots: kept and refreshed when the module stayed,
            tombstoned where RemoveModule would put it when it did not. */
  for (size_t i = 0; i < context->len; i++) {
    struct Module *module = &context->modules[i];
    if (module->name == NULL) continue;

    size_t at = snapshot_len;
    for (size_t s = 0; s < snapshot_len; s++) {
      if (names[s] != NULL && strcmp(names[s], module->name) == 0) {
        at = s;

        break;
      }
    }

    if (at == snapshot_len) {
      if (module->companion >= 0) {
        close(module->companion);
        module->companion = -1;
      }

      if (module->lib_fd >= 0) {
        close(module->lib_fd);
        module->lib_fd = -1;
      }

      free(module->name);
      module->name = NULL;

      continue;
    }

    /* INFO: The library descriptor is re-opened even for a module that did
              not change: a rename update swaps the file under the old name,
              and the descriptor is the only thing that names what is served. */
    if (module->lib_fd >= 0) close(module->lib_fd);
    module->lib_fd = lib_fds[at];

    free(names[at]);
    names[at] = NULL;
  }

  /* INFO: Whatever the snapshot still holds is new: appended after the last
            slot, which is the only place an append cannot move anyone. */
  for (size_t s = 0; s < snapshot_len; s++) {
    if (names[s] == NULL) continue;

    struct Module *grown = realloc(context->modules, (context->len + 1) * sizeof(struct Module));
    if (grown == NULL) {
      LOGE("Failed growing the module table for \"%s\"", names[s]);

      close(lib_fds[s]);
      free(names[s]);

      continue;
    }
    context->modules = grown;

    context->modules[context->len].name = names[s];
    context->modules[context->len].lib_fd = lib_fds[s];
    context->modules[context->len].companion = -1;
    context->len++;
  }

  send_daemon_info(context);
}

/* INFO: Per-connection state handed to every action handler. One struct keeps
         the handler signature stable and lets dispatch stay a plain table. */
struct Client {
  int fd;
  struct Context *context;
  char *restrict *argv;
  bool *first_process;
  /* INFO: Set by the one handler that answers without giving the connection
           back: a control session is a session, not a request, and the accept
           loop closes every connection it is not told to keep. */
  bool keep_open;
};

typedef void (*action_handler_t)(struct Client *client);

struct ActionHandler {
  enum DaemonSocketAction action;
  const char *name;
  action_handler_t handler;
};

static void handle_zygote_injected(struct Client *client) {
  (void) client;

  unix_datagram_sendto(ZYGISK_CONTROLLER_SOCKET, &(uint8_t){ ZYGOTE_INJECTED }, sizeof(uint8_t));
}

/* INFO: A restarted zygote drops every companion, the loader asks for them
         again as it needs them. The module list is re-read here as well, so a
         module installed while the daemon was running is picked up without a
         reboot, and one that disappeared is dropped. */
static void handle_zygote_restart(struct Client *client) {
  (void) client->fd;

  for (size_t i = 0; i < client->context->len; i++) {
    if (client->context->modules[i].companion <= -1) continue;

    close(client->context->modules[i].companion);
    client->context->modules[i].companion = -1;
  }

  /* INFO: The new zygote has not forked anything yet, so the first process
            it specializes should count as "first" again: that is what arms
            the clean mount namespace probe on the loader side. */
  *client->first_process = true;

  reload_modules(client->context);
}

static void handle_get_process_flags(struct Client *client) {
  uint32_t uid = 0;
  ssize_t ret = read_uint32_t(client->fd, &uid);
  ASSURE_SIZE_READ("GetProcessFlags", "uid", ret, sizeof(uid), return);

  /* INFO: Sent by the loader, unused here since only UIDs are queried. */
  char process[PROCESS_NAME_MAX_LEN];
  ret = read_string(client->fd, process, sizeof(process));
  if (ret == -1) {
    LOGE("Failed reading process name.");

    return;
  }

  uint32_t flags = 0;
  if (*client->first_process) {
    flags |= PROCESS_IS_FIRST_STARTED;

    *client->first_process = false;
  }

  /* INFO: "Unknown" must not fall into the else branch below: that branch asks
            about should_umount, and a manager answering yes to it gets the module
            tree reverted out of its own namespace, which blanks every WebUI. So
            an unclassified process is neither manager nor denylisted. */
  enum uid_manager_state manager = uid_is_manager(uid);

  if (manager == UID_MANAGER_YES) {
    flags |= PROCESS_IS_MANAGER;
  } else if (manager == UID_MANAGER_NO) {
    /* INFO: One backend query per request: on the APatch flavour the two
              flags used to cost a config stat each, twice per fork. */
    bool granted_root = false;
    bool should_umount = false;

    uid_query_root(uid, &granted_root, &should_umount);

    if (granted_root) {
      flags |= PROCESS_GRANTED_ROOT;
    }
    if (should_umount) {
      flags |= PROCESS_ON_DENYLIST;
    }
  } else {
    LOGW("Could not tell whether uid %u is the manager; leaving it unclassified.", uid);
  }

  flags |= PROCESS_ROOT_IS_ACTIVE;

  ret = write_uint32_t(client->fd, flags);
  ASSURE_SIZE_WRITE("GetProcessFlags", "flags", ret, sizeof(flags), return);
}

static void handle_get_info(struct Client *client) {
  uint32_t flags = 0;

  flags |= PROCESS_ROOT_IS_ACTIVE;

  ssize_t ret = write_uint32_t(client->fd, flags);
  ASSURE_SIZE_WRITE("GetInfo", "flags", ret, sizeof(flags), return);

  pid_t pid = getpid();
  ret = write_uint32_t(client->fd, (uint32_t)pid);
  ASSURE_SIZE_WRITE("GetInfo", "pid", ret, sizeof(pid), return);

  /* INFO: Tombstoned slots carry no name and are not listed; this answer has
            no index contract, unlike ReadModules, so the list is compacted. */
  size_t modules_count = 0;
  for (size_t i = 0; i < client->context->len; i++) {
    if (client->context->modules[i].name != NULL) modules_count++;
  }

  ret = write_size_t(client->fd, modules_count);
  ASSURE_SIZE_WRITE("GetInfo", "modules_count", ret, sizeof(uint32_t), return);

  for (size_t i = 0; i < client->context->len; i++) {
    if (client->context->modules[i].name == NULL) continue;

    ret = write_string(client->fd, client->context->modules[i].name);
    if (ret == -1) {
      LOGE("Failed writing module name.");

      return;
    }
  }
}

static void handle_read_modules(struct Client *client) {
  /* INFO: The full slot range is sent, empty strings standing in for
            tombstoned slots, so the indexes a zygote derives from this list
            stay those of the daemon's array - which is what
            RequestCompanionSocket and GetModuleDir are addressed with. */
  size_t clen = client->context->len;
  ssize_t ret = write_size_t(client->fd, clen);
  ASSURE_SIZE_WRITE("ReadModules", "len", ret, sizeof(uint32_t), return);

  for (size_t i = 0; i < clen; i++) {
    if (client->context->modules[i].name == NULL) {
      if (write_string(client->fd, "") == -1) {
        LOGE("Failed writing tombstoned module path.");

        return;
      }

      continue;
    }

    char lib_path[PATH_MAX];
    module_lib_path(lib_path, PATH_MAX, client->context->modules[i].name);

    if (write_string(client->fd, lib_path) == -1) {
      LOGE("Failed writing module path.");

      return;
    }
  }
}

static void handle_request_companion_socket(struct Client *client) {
  size_t index = 0;
  ssize_t ret = read_size_t(client->fd, &index);
  ASSURE_SIZE_READ("RequestCompanionSocket", "index", ret, sizeof(uint32_t), return);

  if (index >= client->context->len || client->context->modules[index].name == NULL) {
    LOGE("Invalid module index: %zu", index);

    ret = write_uint8_t(client->fd, 0);
    ASSURE_SIZE_WRITE("RequestCompanionSocket", "response", ret, sizeof(uint8_t), return);

    return;
  }

  struct Module *module = &client->context->modules[index];
  if (module->companion >= 0) {
    if (!check_unix_socket(module->companion, false)) {
      LOGE(" - Companion for module \"%s\" crashed", module->name);

      close(module->companion);
      module->companion = -1;
    }
  }

  /* INFO: Only -1 means "no companion has been attempted yet"; -2 is the
             cached answer of a spawn that found no entry in the library, and
             re-running that spawn on every request would fork a process pair
             each time a companion-less module asks for one. */
  if (module->companion == -1) {
    module->companion = spawn_companion(client->argv, module->name, module->lib_fd);

    if (module->companion >= 0) {
      LOGI(" - Spawned companion for \"%s\": %d", module->name, module->companion);
    } else if (module->companion == -2) {
      LOGE(" - No companion spawned for \"%s\" because it has no entry.", module->name);
    } else {
      LOGE(" - Failed to spawn companion for \"%s\": %s", module->name, strerror(errno));
    }
  }

  /* The companion socket is ready to receive the client fd. */
  if (module->companion >= 0) {
    LOGD(" - Sending companion fd socket of module \"%s\"", module->name);

    if (write_fd(module->companion, client->fd) == -1) {
      LOGE(" - Failed to send companion fd socket of module \"%s\"", module->name);

      ret = write_uint8_t(client->fd, 0);
      ASSURE_SIZE_WRITE("RequestCompanionSocket", "response", ret, sizeof(uint8_t), return);

      close(module->companion);
      module->companion = -1;
    }
  } else {
    /* INFO: The failure itself was already logged when the spawn was
               attempted; only the rejection is left to send here. */
    ret = write_uint8_t(client->fd, 0);
    ASSURE_SIZE_WRITE("RequestCompanionSocket", "response", ret, sizeof(uint8_t), return);
  }
}

static void handle_get_module_dir(struct Client *client) {
  size_t index = 0;
  ssize_t ret = read_size_t(client->fd, &index);
  ASSURE_SIZE_READ("GetModuleDir", "index", ret, sizeof(uint32_t), return);

  if (index >= client->context->len || client->context->modules[index].name == NULL) {
    LOGE("Invalid module index: %zu", index);

    ret = write_uint8_t(client->fd, 0);
    ASSURE_SIZE_WRITE("GetModuleDir", "response", ret, sizeof(uint8_t), return);

    return;
  }

  char module_dir[PATH_MAX];
  module_dir_path(module_dir, PATH_MAX, client->context->modules[index].name);

  int fd = open(module_dir, O_RDONLY | O_CLOEXEC);
  if (fd == -1) {
    PLOGE("Failed opening module directory");

    return;
  }

  if (write_fd(client->fd, fd) == -1) {
    PLOGE("Failed sending module directory fd");

    close(fd);

    return;
  }

  close(fd);
}

static void handle_update_mount_namespace(struct Client *client) {
  uint32_t target_process = 0;
  ssize_t ret = read_uint32_t(client->fd, &target_process);
  ASSURE_SIZE_READ("UpdateMountNamespace", "pid", ret, sizeof(target_process), return);

  uint8_t mns_state = 0;
  ret = read_uint8_t(client->fd, &mns_state);
  ASSURE_SIZE_READ("UpdateMountNamespace", "mns_state", ret, sizeof(mns_state), return);

  uint32_t our_pid = (uint32_t)getpid();
  ret = write_uint32_t(client->fd, our_pid);
  ASSURE_SIZE_WRITE("UpdateMountNamespace", "our_pid", ret, sizeof(our_pid), return);

  /* INFO: Clean is the only state this protocol carries; anything else is a
            loader this daemon does not match. */
  if (mns_state > (uint8_t)Clean) {
    LOGE("Invalid mount namespace state: %u", (unsigned int)mns_state);

    ret = write_uint32_t(client->fd, (uint32_t)0);
    ASSURE_SIZE_WRITE("UpdateMountNamespace", "ns_fd", ret, sizeof(uint32_t), return);

    return;
  }

  int ns_fd = save_mns_fd((pid_t)target_process);
  if (ns_fd == -1) {
    LOGE("Failed to save mount namespace fd for pid %u: %s", target_process, strerror(errno));

    ret = write_uint32_t(client->fd, (uint32_t)0);
    ASSURE_SIZE_WRITE("UpdateMountNamespace", "ns_fd", ret, sizeof(ns_fd), return);

    return;
  }

  ret = write_uint32_t(client->fd, (uint32_t)ns_fd);
  ASSURE_SIZE_WRITE("UpdateMountNamespace", "ns_fd", ret, sizeof(ns_fd), return);
}

static void handle_remove_module(struct Client *client) {
  size_t index = 0;
  ssize_t ret = read_size_t(client->fd, &index);
  ASSURE_SIZE_READ("RemoveModule", "index", ret, sizeof(uint32_t), return);

  if (index >= client->context->len) {
    LOGE("Invalid module index: %zu", index);

    ret = write_uint8_t(client->fd, 0);
    ASSURE_SIZE_WRITE("RemoveModule", "response", ret, sizeof(uint8_t), return);

    return;
  }

  /* INFO: The slot is tombstoned instead of removed: zygotes that already read
            the module list hold indices into it, and compacting the array
            shifts every module after the slot to the left, so a companion or
            module-dir request from a still-running zygote would land on the
            wrong module. A tombstone keeps the positions stable; ReadModules
            hands out an empty path for it and new zygotes skip the slot. */
  struct Module *module = &client->context->modules[index];
  if (module->companion >= 0) {
    close(module->companion);
    module->companion = -1;
  }

  free(module->name);
  module->name = NULL;

  if (module->lib_fd >= 0) {
    close(module->lib_fd);
    module->lib_fd = -1;
  }

  ret = write_uint8_t(client->fd, 1);
  ASSURE_SIZE_WRITE("RemoveModule", "response", ret, sizeof(uint8_t), return);
}

/* INFO: Ordered by action value; the table is small enough that a linear scan
         costs less than the socket round trip around it. */
static const struct ActionHandler kActionHandlers[] = {
  { ZygoteInjected,         "ZygoteInjected",         handle_zygote_injected         },
  { GetProcessFlags,        "GetProcessFlags",        handle_get_process_flags       },
  { GetInfo,                "GetInfo",                handle_get_info                },
  { ReadModules,            "ReadModules",            handle_read_modules            },
  { RequestCompanionSocket, "RequestCompanionSocket", handle_request_companion_socket },
  { GetModuleDir,           "GetModuleDir",           handle_get_module_dir          },
  { ZygoteRestart,          "ZygoteRestart",          handle_zygote_restart          },
  { UpdateMountNamespace,   "UpdateMountNamespace",   handle_update_mount_namespace  },
  { RemoveModule,           "RemoveModule",           handle_remove_module           }
};

static const struct ActionHandler *find_action_handler(enum DaemonSocketAction action) {
  for (size_t i = 0; i < sizeof(kActionHandlers) / sizeof(kActionHandlers[0]); i++) {
    if (kActionHandlers[i].action == action) return &kActionHandlers[i];
  }

  return NULL;
}

static void serve_accepted(int client_fd, struct Context *restrict context, char *restrict argv[], bool *first_process) {
  /* INFO: Bound a single exchange so a stuck client cannot stall the zygote
            forks waiting behind it. A control session clears this for itself:
            it is read while it is quiet, which is most of its life. */
  struct timeval timeout = { .tv_sec = DAEMON_EXCHANGE_TIMEOUT_SECS, .tv_usec = 0 };
  setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  uint8_t action8 = 0;
  ssize_t len = read_uint8_t(client_fd, &action8);
  if (len == -1) {
    PLOGE("read action");

    close(client_fd);

    return;
  } else if (len == 0) {
    /* INFO: A client that connects and leaves used to end the loop and take
              the daemon down; only a failed accept should do that. */
    LOGI("Client disconnected before sending an action");

    close(client_fd);

    return;
  }

  const struct ActionHandler *handler = find_action_handler((enum DaemonSocketAction)action8);
  if (handler == NULL) {
    LOGE("Unknown daemon action: %u", (unsigned int)action8);

    close(client_fd);

    return;
  }

  struct Client client = {
    .fd            = client_fd,
    .context       = context,
    .argv          = argv,
    .first_process = first_process,
    .keep_open     = false
  };

  handler->handler(&client);

  if (!client.keep_open) close(client_fd);
}

static void serve_loop(int socket_fd, struct Context *restrict context, char *restrict argv[]) {
  bool first_process = true;

  struct pollfd polled = { .fd = socket_fd, .events = POLLIN, .revents = 0 };

  while (1) {
    polled.revents = 0;

    const int ready = poll(&polled, 1, -1);
    if (ready == -1) {
      /* A signal (EINTR) only interrupts this one wait; keep serving. */
      if (errno == EINTR) continue;

      PLOGE("poll");

      return;
    }

    if ((polled.revents & POLLIN) == 0) continue;

    /* INFO: CLOEXEC on the accepted fd keeps client connections out of the
              companion processes forked while a handler runs. */
    int client_fd = accept4(socket_fd, NULL, NULL, SOCK_CLOEXEC);
    if (client_fd == -1) {
      /* A signal (EINTR) only interrupts this one wait; keep serving. */
      if (errno == EINTR) continue;

      /* INFO: These describe this one connection, or a shortage that clears,
                not a dead listener. Returning here used to end serve_loop and
                take the daemon down with it - every cached companion included -
                until the monitor noticed and started another one. */
      if (errno == ECONNABORTED || errno == EMFILE || errno == ENFILE ||
          errno == ENOBUFS || errno == ENOMEM) {
        PLOGE("accept");

        /* INFO: A shortage needs a moment to clear; without a pause this
                  would spin on it. */
        usleep(100000);

        continue;
      }

      PLOGE("accept");

      return;
    }

    serve_accepted(client_fd, context, argv, &first_process);
  }
}

void zygiskd_start(char *restrict argv[]) {
  /* load_modules and the socket handlers free through free_modules, so the
     context must start as a clean zeroed slate on every path. */
  struct Context context = { 0 };

  struct root_impl impl;
  get_impl(&impl);

  load_modules(&context);
  send_daemon_info(&context);

  LOGI("Sent root implementation and modules information to controller socket");

  int socket_fd = create_daemon_socket();
  if (socket_fd == -1) {
    LOGE("Failed creating daemon socket");

    free_modules(&context);

    root_impl_cleanup();

    return;
  }

  struct sigaction sa = { .sa_handler = SIG_IGN };
  sigaction(SIGPIPE, &sa, NULL);

  serve_loop(socket_fd, &context, argv);

  close(socket_fd);
  free_modules(&context);
  root_impl_cleanup();
}
