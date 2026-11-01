#include <ctype.h>
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
#include "zn_control_protocol.h"
#include "zn_status.h"
#include "zygisk_paths.h"
#include "zn_targets.h"
#include "root_impl/common.h"
#include "utils.h"
#include "vexcore.h"

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

/* INFO: Zygisk Next modules ship zn_modules.txt instead of a Zygisk library,
         they are kept apart so the loader indexes stay those of the modules it
         can actually load. The targets and companion flag are read from the
         file so the controller can surface them in the UI. */
struct ZnModule {
  char *name;
  bool companion;
  char **targets;
  size_t targets_len;
};

struct Context {
  struct Module *modules;
  size_t len;

  struct ZnModule *zn_modules;
  size_t zn_len;

  struct ZnCompanion *zn_companions;
  size_t zn_companions_len;

  /* INFO: The HyperOS runtime's control sessions, one descriptor per forked
           application that still holds one. They are sessions and not requests:
           the connection is accepted, answered once, and then kept open for as
           long as the process behind it reports - which is why they are watched
           rather than served.

           Nothing is accumulated per report: what a session carries is the
           runtime's own record of what it did, and the daemon's side of it is
           the log line each record produces. A fork with no Zygisk Next status
           surface to answer has no table to keep, and one that nobody reads
           would only go stale. */
  int *zn_sessions;
  size_t zn_sessions_len;

  /* INFO: The list grows by doubling and never shrinks, like the poll set
           that reads it: on a HyperOS device a session is opened for every
           application the spawner forks, so the entry count climbs for as long
           as the daemon runs, and growing it one entry at a time copied the
           whole list on each of those. The peak is what it has to be sized
           for. */
  size_t zn_sessions_capacity;
};

/* INFO: A Zygisk Next library resolved for one target: its path, whether the
         module asked for a companion, and the fd of the opened file. */
struct ZnModuleFile {
  char *lib_path;
  /* INFO: The module directory the library was resolved from, which is what the
           module is named by: in the plan the loader hands out, in the log, and
           in the runtime's report of a specialization. */
  char *module_id;
  bool companion;
  int fd;
  bool owned;  /* INFO: false when fd is a daemon-cached shared memfd. */
};

/* INFO: One live Zygisk Next companion process, kept for the daemon's
         lifetime and handed out by descriptor duplication. Keyed by library
         path, since ZN companions are per module library, not per request. */
struct ZnCompanion {
  char *lib_path;
  int fd;
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
  controller_dgram_put_u8(&dgram, 0);

  controller_dgram_send(&dgram);
}

/* INFO: A standard Zygisk module entry: the type byte tells the monitor the
           module does not target Zygisk Next. */
static void send_module_info(const char *name) {
  struct controller_dgram dgram = { .len = 0 };

  if (!controller_dgram_put_u8(&dgram, DAEMON_MODULE_ENTRY) ||
      !controller_dgram_put_string(&dgram, name) ||
      !controller_dgram_put_u8(&dgram, 0)) {
    LOGE("The module entry for \"%s\" does not fit one datagram", name);

    send_minimal_module_entry();

    return;
  }

  controller_dgram_send(&dgram);
}

/* INFO: Zygisk Next modules also carry the companion flag and every target
         of their zn_modules.txt, so the monitor can show them. Targets past
         the buffer are dropped with the count the record actually carries -
         the entry stays parseable, which a truncated one would not be. */
static void send_zn_module_info(const struct ZnModule *module) {
  struct controller_dgram dgram = { .len = 0 };

  if (!controller_dgram_put_u8(&dgram, DAEMON_MODULE_ENTRY) ||
      !controller_dgram_put_string(&dgram, module->name) ||
      !controller_dgram_put_u8(&dgram, 1) ||
      !controller_dgram_put_u8(&dgram, module->companion ? 1 : 0) ||
      !controller_dgram_put_u32(&dgram, 0)) {
    LOGE("The Zygisk Next entry for \"%s\" does not fit one datagram", module->name);

    send_minimal_module_entry();

    return;
  }

  /* INFO: The count field was written as zero above; its position is where
            the real count goes once the targets that fit are known. */
  const size_t count_at = dgram.len - sizeof(uint32_t);

  size_t targets_sent = 0;
  for (size_t i = 0; i < module->targets_len; i++) {
    struct controller_dgram probe = dgram;

    if (!controller_dgram_put_string(&probe, module->targets[i])) break;

    dgram = probe;
    targets_sent++;
  }

  uint32_t sent = (uint32_t)targets_sent;
  memcpy(&dgram.bytes[count_at], &sent, sizeof(sent));

  controller_dgram_send(&dgram);
}

/* INFO: Reads zn_modules.txt and collects the targets, one per line ("name="
         or "path=" as the first token), plus whether any line asks for a
         companion, which is only matched between the target and the library.
         The daemon is the only side that parses this file: the loader takes the
         plan over the protocol. */
static void parse_zn_module_file(const char *module_dir, struct ZnModule *module) {
  char zn_path[PATH_MAX];
  snprintf(zn_path, PATH_MAX, "%s/zn_modules.txt", module_dir);

  FILE *fp = fopen(zn_path, "re");
  if (fp == NULL) return;

  char *line = NULL;
  size_t line_capacity = 0;
  ssize_t length;

  while ((length = getline(&line, &line_capacity, fp)) > 0) {
    char *tokens[8];
    size_t token_count = 0;

    const char *cursor = line;
    while (*cursor != '\0' && token_count < 8) {
      while (*cursor != '\0' && isspace((unsigned char)*cursor)) cursor++;
      if (*cursor == '\0') break;

      const char *start = cursor;
      while (*cursor != '\0' && !isspace((unsigned char)*cursor)) cursor++;

      size_t token_len = (size_t)(cursor - start);
      tokens[token_count] = malloc(token_len + 1);
      if (tokens[token_count] == NULL) break;
      memcpy(tokens[token_count], start, token_len);
      tokens[token_count][token_len] = '\0';

      token_count++;
    }

    if (token_count >= 2) {
      for (size_t i = 1; i + 1 < token_count; i++) {
        if (strcmp(tokens[i], "companion") == 0) module->companion = true;
      }

      char **tmp = realloc(module->targets, (module->targets_len + 1) * sizeof(char *));
      if (tmp != NULL) {
        module->targets = tmp;
        module->targets[module->targets_len++] = tokens[0];
        tokens[0] = NULL; /* INFO: Ownership moves into the array */
      }
    }

    for (size_t i = 0; i < token_count; i++) free(tokens[i]);
  }

  free(line);
  fclose(fp);
}

static bool add_zn_module(struct Context *restrict context, const char *name) {
  struct ZnModule *tmp = realloc(context->zn_modules, (context->zn_len + 1) * sizeof(struct ZnModule));
  if (tmp == NULL) {
    LOGE("Failed reallocating memory for Zygisk Next modules.");

    return false;
  }
  context->zn_modules = tmp;

  struct ZnModule *module = &context->zn_modules[context->zn_len];
  module->name = strdup(name);
  if (module->name == NULL) {
    LOGE("Failed to strdup for the Zygisk Next module \"%s\": %s", name, strerror(errno));

    /* INFO: The name is freed here because free_modules only walks the
              entries zn_len counts, and this one was never counted - leaving
              it behind leaks one strdup per failure for the daemon's life. */
    free(module->name);
    module->name = NULL;

    return false;
  }

  module->companion = false;
  module->targets = NULL;
  module->targets_len = 0;

  char module_dir[PATH_MAX];
  module_dir_path(module_dir, PATH_MAX, name);

  parse_zn_module_file(module_dir, module);

  context->zn_len++;

  return true;
}

/* INFO: Declared here because load_modules bails out through it, and it is
         defined further down where the rest of the context handling lives. */
static void free_modules(struct Context *restrict context);

/* INFO: Same story: the Zygisk Next parse cache lives with the request
         handlers further down, and free_modules drops it on every reload. */
static void zn_parse_cache_clear(void);

static void load_modules(struct Context *restrict context) {
  context->len = 0;
  context->modules = NULL;
  context->zn_len = 0;
  context->zn_modules = NULL;

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

    char zn_modules[PATH_MAX];
    module_file_path(zn_modules, PATH_MAX, name, "zn_modules.txt");

    /* INFO: Both mechanisms serve a module rather than one excluding the other,
              which is what LSPosed needs: it ships a zn_modules.txt (it wants a
              ZN-aware provider) but only ever exports zygisk_module_entry.
              Treating them as exclusive sends it down a ZN path it cannot load
              and drops it from the standard path it could. Listing it in both
              costs nothing - the ZN load finds no zn_module and gives up. */
    if (access(zn_modules, F_OK) == 0) {
      LOGI("Found Zygisk Next module \"%s\"", name);

      /* INFO: Its failure is reported rather than dropped: the module would
                otherwise be absent from the list the injector reads, with
                nothing on this side to say the record was never made. */
      if (!add_zn_module(context, name)) {
        LOGE("Failed to record the Zygisk Next module \"%s\"", name);
      }
    }

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

/* INFO: Closing the cached end is not enough to retire a companion: its control
         socket is handed to every asker, so any process still holding a duplicate
         keeps the peer alive and the companion would sit in recvmsg long after the
         daemon let go, only to be joined by a fresh one after the next zygote
         restart. shutdown() acts on the socket itself rather than on one
         descriptor, so every holder sees the close at once and the companion
         exits through its own "control socket closed" path.

         The double fork hands the companion to init, so the daemon cannot and
         must not waitpid it. */
static void release_zn_companion_fd(int fd) {
  if (fd < 0) return;

  shutdown(fd, SHUT_RDWR);
  close(fd);
}

static void free_zn_companions(struct Context *restrict context) {
  for (size_t i = 0; i < context->zn_companions_len; i++) {
    free(context->zn_companions[i].lib_path);
    release_zn_companion_fd(context->zn_companions[i].fd);
  }

  free(context->zn_companions);
  context->zn_companions = NULL;
  context->zn_companions_len = 0;
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

  for (size_t i = 0; i < context->zn_len; i++) {
    free(context->zn_modules[i].name);

    for (size_t j = 0; j < context->zn_modules[i].targets_len; j++) {
      free(context->zn_modules[i].targets[j]);
    }

    free(context->zn_modules[i].targets);
  }

  free(context->zn_modules);
  context->zn_modules = NULL;
  context->zn_len = 0;

  free_zn_companions(context);

  /* INFO: The parse cache is stat-validated anyway; dropping it here (module
            reload, daemon exit) just keeps the resident set honest. */
  zn_parse_cache_clear();
}

static void free_zn_module_files(struct ZnModuleFile *files, size_t len) {
  for (size_t i = 0; i < len; i++) {
    free(files[i].lib_path);
    free(files[i].module_id);
    /* INFO: Shared memfds belong to the staging cache and outlive this
              request on purpose; only per-call copies are ours to close. */
    if (files[i].owned && files[i].fd >= 0) close(files[i].fd);
  }

  free(files);
}

/* INFO: Splits one zn_modules.txt line, which reads
         "<name=|path=><target> [companion] <library>". The library is always
         the last token and "companion" may sit anywhere between the target and
         it, so only that range is scanned for the flag. */
/* INFO: The line parser, forwarded to the Rust half (see vexcore.h).

         What it accepts has not changed: `name=` or `path=` to say what the
         target is, an optional `companion` anywhere between it and the library,
         and the library last. Neither has the rule that makes a relative
         library path relative to the module directory rather than to wherever
         the daemon happens to be running.

         What did: the C version allocated both strings, so the caller had two
         failure paths that were about the allocator and not about the line. The
         answers come back in this frame's buffers, and the two copies below are
         the caller's own lifetime rather than the parser's - which is the same
         pair of `strdup`s the function used to end with, minus the question of
         what a half-parsed line means. */
static bool parse_zn_line(const char *module_dir, const char *line, bool *is_name, char **target, bool *companion, char **lib_path) {
  char target_buf[PATH_MAX];
  char lib_buf[PATH_MAX];

  if (!vexcore_zn_parse_line(line, module_dir, is_name, companion,
                             target_buf, sizeof(target_buf),
                             lib_buf, sizeof(lib_buf))) {
    return false;
  }

  char *parsed_target = strdup(target_buf);
  if (parsed_target == NULL) {
    LOGE("Failed allocating a Zygisk Next target");

    return false;
  }

  char *resolved = strdup(lib_buf);
  if (resolved == NULL) {
    LOGE("Failed allocating a Zygisk Next library path");

    free(parsed_target);

    return false;
  }

  *target = parsed_target;
  *lib_path = resolved;

  return true;
}

/* INFO: Whether one manifest line selects this process.

         A name target is answered by the executable's own name, with the
         zygote-class spelling resolved the way zn_targets.h explains.

         A path target names the executable, which is what /proc/self/exe
         answers - except on the builds where the HyperOS runtime is hosted by
         an ART binary and the image the manifest means is mapped into it rather
         than exec'd. The runtime scan knows that image's path, so the loader
         hands it over as a second answer, and a target that spells it selects
         this process whichever file it exec'd. An empty second answer is "there
         is no second answer", which is every process that does not host the
         runtime. */
static bool zn_matches_target(const char *target, bool is_name, const char *process_name, const char *process_path, const char *image_path) {
  if (is_name) {
    if (zn_target_is_zygote_class(target)) return zn_process_is_zygote_class(process_name);

    return strcmp(process_name, target) == 0;
  }

  if (strcmp(process_path, target) == 0) return true;

  return image_path != NULL && image_path[0] != '\0' && strcmp(image_path, target) == 0;
}

/* INFO: Every exchange the daemon takes part in is bound by this, client
           and companion sockets alike: a stuck peer must never stall the
           zygote forks waiting behind it.

           Three, because three is the whole budget the loader side gives any
           request it makes (REZYGISKD_IO_TIMEOUT_SEC in the loader's
           daemon.c): serving a client for longer than that only delays every
           fork queued behind it, for a caller that has already given up. */
#define DAEMON_EXCHANGE_TIMEOUT_SECS 3

/* INFO: The one exception: a HyperOS control session sits quiet between the
           reports of the applications that inherited it, so it gets a
           generous deadline instead of the exchange budget - generous, and
           not infinite, because half a record written by any of those
           applications must not block the daemon's poll loop forever. */
#define ZN_SESSION_READ_TIMEOUT_SECS 30

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

/* Spawns the companion of a Zygisk Next module. Takes a path rather than a
   module name because ZN modules are not tracked by index; the library is
   copied into a memfd here since the companion cannot read /data/adb/modules. */
static int spawn_zn_companion(char *restrict argv[], const char *restrict lib_path) {
  int daemon_fd = -1;
  if (exec_companion(argv, "zn-companion", "zn-companion", &daemon_fd) == -1) return -1;

  if (write_string(daemon_fd, lib_path) == -1) {
    LOGE("Failed writing the Zygisk Next library path.");

    close(daemon_fd);

    return -1;
  }

  bool shared = false;
  int lib_fd = create_library_fd(lib_path, &shared);
  if (lib_fd == -1) {
    LOGE("Failed handing over \"%s\"", lib_path);

    close(daemon_fd);

    return -1;
  }

  if (write_fd(daemon_fd, lib_fd) == -1) {
    LOGE("Failed sending the Zygisk Next library fd.");

    if (!shared) close(lib_fd);

    close(daemon_fd);

    return -1;
  }

  if (!shared) close(lib_fd);

  uint8_t response = 0;
  if (read_uint8_t(daemon_fd, &response) <= 0) {
    LOGE("Failed reading the Zygisk Next companion response.");

    close(daemon_fd);

    return -1;
  }

  if (response != 1) {
    LOGE("The Zygisk Next companion rejected \"%s\"", lib_path);

    close(daemon_fd);

    return -1;
  }

  return daemon_fd;
}

/* Walks every Zygisk Next module and resolves the libraries targeting this
   process. The daemon opens the files itself because a non-root target cannot
   read /data/adb/modules, which is the whole point of handing them over as
   file descriptors. */
/* INFO: Parsed zn_modules.txt of one module directory, cached because
         collect_zn_modules walks every module for every fork. Re-parsed when
         the file's stat identity changes, which is how a module update takes
         effect; the disable marker stays a per-request check, which is what
         makes toggling a module work without a daemon restart. */
struct zn_cached_line {
  bool is_name;
  bool companion;
  char *target;
  char *lib_path;
};

struct zn_cached_module {
  char *dir_name;
  struct stat st;
  bool valid;

  struct zn_cached_line *lines;
  size_t lines_len;
};

static struct zn_cached_module *zn_parse_cache;
static size_t zn_parse_cache_len;

/* INFO: The /data/adb/modules listing, cached against the directory's stat
         identity: entries appear or disappear through the directory itself,
         so its mtime covers module installs and removals. Everything inside
         a module directory (disable marker, zn_modules.txt identity) stays a
         per-request check on purpose. */
struct zn_dir_entry {
  char *name;
};

static struct zn_dir_entry *zn_dir_cache;
static size_t zn_dir_cache_len;
static struct stat zn_dir_st;
static bool zn_dir_valid;

/* INFO: A module names its library as a relative path or as an absolute one,
         so nothing stops a zn_modules.txt from pointing at another module's
         directory or at a system file. Only a library that really lives inside
         its own module directory is accepted, which is also what makes the
         per-module disable and remove switches mean anything. `resolved`
         receives the canonical path, so every path this daemon hands out later
         is one that can be compared as a string. */
static bool zn_library_in_module_dir(const char *module_dir, const char *lib_path, char *resolved, size_t resolved_size) {
  char real_dir[PATH_MAX];
  if (realpath(module_dir, real_dir) == NULL) return false;

  char real_lib[PATH_MAX];
  if (realpath(lib_path, real_lib) == NULL) return false;

  size_t dir_len = strlen(real_dir);
  size_t lib_len = strlen(real_lib);

  /* INFO: The separator is required as well: "/data/adb/modules/foo" must not
            accept "/data/adb/modules/foobar/lib.so". */
  if (lib_len <= dir_len) return false;
  if (strncmp(real_lib, real_dir, dir_len) != 0) return false;
  if (real_lib[dir_len] != '/') return false;

  if (lib_len >= resolved_size) return false;

  memcpy(resolved, real_lib, lib_len + 1);

  return true;
}

/* INFO: A Zygisk Next library is loaded by the target process itself, so one
         built for the other bitness can never work there. Shipping a 32- and a
         64-bit build and listing both is the common way modules are packaged,
         so this is a normal case and not a module's mistake: skipping it here
         keeps a guaranteed-failing dlopen out of every target.

         Twenty bytes rather than five, because a class that matches says nothing
         about the rest of the header: a shared object is ET_DYN, is
         little-endian on every platform this runs on, and names the machine it
         was assembled for. An ELF of the right width built for another
         architecture is refused here, where the reason is known, instead of
         failing inside the loader with nothing to say. */
static bool zn_library_matches_abi(const char *path) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd == -1) return false;

  unsigned char header[20];
  size_t filled = 0;

  while (filled < sizeof(header)) {
    ssize_t got = read(fd, header + filled, sizeof(header) - filled);
    if (got == -1) {
      if (errno == EINTR) continue;

      break;
    }

    if (got == 0) break;

    filled += (size_t)got;
  }

  close(fd);

  if (filled < sizeof(header)) return false;
  if (memcmp(header, ELFMAG, SELFMAG) != 0) return false;
  if (header[EI_DATA] != ELFDATA2LSB) return false;

#if defined(__LP64__)
  if (header[EI_CLASS] != ELFCLASS64) return false;
#else
  if (header[EI_CLASS] != ELFCLASS32) return false;
#endif

  uint16_t type = 0;
  uint16_t machine = 0;

  memcpy(&type, header + 16, sizeof(type));
  memcpy(&machine, header + 18, sizeof(machine));

  /* INFO: ET_DYN rather than either executable type: what is handed over is
            loaded, not run, so the relocatable form is the only one that can
            work. */
  if (type != ET_DYN) return false;

#if defined(__aarch64__)
  return machine == EM_AARCH64;
#elif defined(__arm__)
  return machine == EM_ARM;
#elif defined(__x86_64__)
  return machine == EM_X86_64;
#elif defined(__i386__)
  return machine == EM_386;
#else
  return false;
#endif
}

static void zn_parse_cache_free_lines(struct zn_cached_module *module) {
  for (size_t i = 0; i < module->lines_len; i++) {
    free(module->lines[i].target);
    free(module->lines[i].lib_path);
  }

  free(module->lines);
  module->lines = NULL;
  module->lines_len = 0;
  module->valid = false;
}

static void zn_parse_cache_clear(void) {
  for (size_t i = 0; i < zn_parse_cache_len; i++) {
    zn_parse_cache_free_lines(&zn_parse_cache[i]);
    free(zn_parse_cache[i].dir_name);
  }

  free(zn_parse_cache);
  zn_parse_cache = NULL;
  zn_parse_cache_len = 0;

  for (size_t i = 0; i < zn_dir_cache_len; i++) {
    free(zn_dir_cache[i].name);
  }

  free(zn_dir_cache);
  zn_dir_cache = NULL;
  zn_dir_cache_len = 0;
  zn_dir_valid = false;
}

/* INFO: The cache slot for `dir_name`, created and registered when there is
         none yet. NULL only when the table could not grow or the name could not
         be copied. */
static struct zn_cached_module *zn_parse_cache_slot(const char *dir_name) {
  for (size_t i = 0; i < zn_parse_cache_len; i++) {
    if (strcmp(zn_parse_cache[i].dir_name, dir_name) == 0) return &zn_parse_cache[i];
  }

  struct zn_cached_module *tmp = realloc(zn_parse_cache, (zn_parse_cache_len + 1) * sizeof(struct zn_cached_module));
  if (tmp == NULL) {
    LOGE("Failed growing the Zygisk Next parse cache");

    return NULL;
  }

  zn_parse_cache = tmp;

  struct zn_cached_module *module = &zn_parse_cache[zn_parse_cache_len];
  memset(module, 0, sizeof(*module));

  module->dir_name = strdup(dir_name);
  if (module->dir_name == NULL) return NULL;

  zn_parse_cache_len++;

  return module;
}

/* INFO: Reads `zn_file` into `module`, replacing whatever rows it held.
         Returns false when the file could not be opened, which leaves the slot
         invalid so the next call tries again.

         Everything that costs a syscall runs here, once per file change, and
         not wherever the rows are consumed: realpath() stats every path
         component and the ABI check opens the file, while the rows are walked
         for every module on every fork. What gets cached is the canonical path,
         so the per-fork path stays a plain string compare. */
static bool zn_parse_cache_read(struct zn_cached_module *module,
                                const char *module_dir, const char *zn_file) {
  FILE *fp = fopen(zn_file, "re");
  if (fp == NULL) return false;

  char *line = NULL;
  size_t line_capacity = 0;
  ssize_t length;

  while ((length = getline(&line, &line_capacity, fp)) > 0) {
    while (length > 0 && isspace((unsigned char)line[length - 1])) line[--length] = '\0';
    if (length == 0) continue;

    bool is_name = false;
    bool companion = false;
    char *target = NULL;
    char *lib_path = NULL;

    if (!parse_zn_line(module_dir, line, &is_name, &target, &companion, &lib_path)) continue;

    char canonical[PATH_MAX];

    if (!zn_library_in_module_dir(module_dir, lib_path, canonical, sizeof(canonical))) {
      LOGW("The Zygisk Next library \"%s\" of \"%s\" cannot be resolved inside its module directory, skipping", lib_path, module->dir_name);

      free(target);
      free(lib_path);

      continue;
    }

    free(lib_path);

    lib_path = strdup(canonical);

    if (lib_path == NULL) {
      LOGE("Failed copying the canonical path of \"%s\"", canonical);

      free(target);

      continue;
    }

    if (!zn_library_matches_abi(lib_path)) {
      LOGD("The Zygisk Next library \"%s\" is not built for this ABI, skipping", lib_path);

      free(target);
      free(lib_path);

      continue;
    }

    struct zn_cached_line *tmp = realloc(module->lines, (module->lines_len + 1) * sizeof(struct zn_cached_line));
    if (tmp == NULL) {
      LOGE("Failed growing the parsed rows of \"%s\"", module->dir_name);

      free(target);
      free(lib_path);

      break;
    }

    module->lines = tmp;
    module->lines[module->lines_len].is_name = is_name;
    module->lines[module->lines_len].companion = companion;
    module->lines[module->lines_len].target = target;
    module->lines[module->lines_len].lib_path = lib_path;
    module->lines_len++;
  }

  free(line);
  fclose(fp);

  return true;
}

/* INFO: The parsed rows of `dir_name`, from the cache when the file has not
         changed since it was read. What is left here is the decision about the
         file - gone, unchanged, or new - since the reading and the slot
         bookkeeping are their own steps. */
static struct zn_cached_module *zn_parse_cache_get(const char *dir_name, const char *module_dir, const char *zn_file) {
  struct zn_cached_module *module = zn_parse_cache_slot(dir_name);
  if (module == NULL) return NULL;

  struct stat st;
  if (stat(zn_file, &st) == -1) {
    if (module->valid) {
      LOGI("The Zygisk Next list of \"%s\" disappeared", dir_name);

      zn_parse_cache_free_lines(module);
    }

    return NULL;
  }

  if (module->valid && stat_identity_same(&module->st, &st)) return module;

  /* INFO: New or changed file: drop the old rows and parse afresh. */
  zn_parse_cache_free_lines(module);

  if (!zn_parse_cache_read(module, module_dir, zn_file)) return NULL;

  module->st = st;
  module->valid = true;

  return module;
}

/* INFO: How many libraries one process's plan is deduplicated against. A plan
         is a handful of entries; this only exists so the per-fork path cannot
         grow an allocation. Past the cap a duplicate slips through to the
         loader's own already-loaded check, which is cheaper than the growth
         would be. */
#define ZN_PLAN_DEDUP_MAX 32

/* INFO: The identity a library is deduplicated by: the file, not the name it
         was reached through. Two names can be one file - a hard link, a second
         module directory holding another link to the same library - and what
         matters is that it is loaded once, because loading it twice installs
         its hooks twice. The canonical path is the cheap answer and this is the
         exact one; the stat is taken on the path that already matched, once per
         matched row and not once per fork. */
struct zn_served_library {
  dev_t dev;
  ino_t inode;
};

/* INFO: The listing of the module directory, rebuilt in place when the
         directory is gone from the table or its identity changed; otherwise it
         stays as it is. Kept across calls because it is read on every fork. */
static int compare_zn_dir_entries(const void *left, const void *right) {
  const struct zn_dir_entry *a = (const struct zn_dir_entry *)left;
  const struct zn_dir_entry *b = (const struct zn_dir_entry *)right;

  return strcmp(a->name, b->name);
}
static bool refresh_module_dir_cache(const struct stat *dir_st) {
  if (zn_dir_valid && stat_identity_same(dir_st, &zn_dir_st)) return true;

  for (size_t i = 0; i < zn_dir_cache_len; i++) {
    free(zn_dir_cache[i].name);
  }

  zn_dir_cache_len = 0;

  DIR *dir = opendir(ZYGISK_MODULES_DIR);
  if (dir == NULL) {
    LOGE("Failed opening %s: %s", ZYGISK_MODULES_DIR, strerror(errno));

    zn_dir_valid = false;

    return false;
  }

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN) continue;
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, "rezygisk") == 0) continue;

    struct zn_dir_entry *tmp = realloc(zn_dir_cache, (zn_dir_cache_len + 1) * sizeof(struct zn_dir_entry));
    if (tmp == NULL) {
      LOGE("Failed growing the module directory listing");

      break;
    }

    zn_dir_cache = tmp;
    zn_dir_cache[zn_dir_cache_len].name = strdup(entry->d_name);
    if (zn_dir_cache[zn_dir_cache_len].name == NULL) break;

    zn_dir_cache_len++;
  }

  closedir(dir);

  /* INFO: Sorted, so what a process is served does not depend on the order the
             directory hands its entries back: two modules that both name the
             same process are listed by name, the slots the loader indexes them
             by are the same on every boot, and a report names the module it is
             about whichever way the filesystem felt that day. */
  if (zn_dir_cache_len > 1) {
    qsort(zn_dir_cache, zn_dir_cache_len, sizeof(struct zn_dir_entry), compare_zn_dir_entries);
  }

  zn_dir_st = *dir_st;
  zn_dir_valid = true;

  return true;
}

static bool collect_zn_modules(const char *process_name, const char *process_path, const char *image_path, struct ZnModuleFile **out, size_t *out_len) {
  *out = NULL;
  *out_len = 0;

  size_t capacity = 0;

  /* INFO: Two modules may list the same library, and loading it twice would
           install its hooks twice. The identity is the file's rather than the
           path's: a hard link keeps two names for one file, and the second one
           is a library that must not be loaded a second time. */
  struct zn_served_library served[ZN_PLAN_DEDUP_MAX];
  size_t served_len = 0;

  /* INFO: What "why did this process get nothing" needs, and the only place
           that can answer it: how many module directories were walked, how many
           of them held a list at all, how many rows those lists had, and how
           many of those named this process. An empty plan looks the same from
           the loader whichever of those went wrong, and every one of them has
           been mistaken for one of the others while this was being chased. */
  size_t dirs_walked = 0;
  size_t lists_valid = 0;
  size_t rows_examined = 0;
  size_t rows_matched = 0;

  /* INFO: The first row that did not name this process, kept only to be shown
            when nothing did: it is what a reader compares against the name the
            process reported, and that comparison is the whole diagnosis. */
  const char *example_target = NULL;

  struct stat dir_st;
  if (stat(ZYGISK_MODULES_DIR, &dir_st) == -1) {
    LOGE("Failed stating %s: %s", ZYGISK_MODULES_DIR, strerror(errno));

    return false;
  }

  if (!refresh_module_dir_cache(&dir_st)) return false;

  for (size_t i = 0; i < zn_dir_cache_len; i++) {
    const char *entry_name = zn_dir_cache[i].name;

    dirs_walked++;

    char module_dir[PATH_MAX];
    module_dir_path(module_dir, PATH_MAX, entry_name);

    char disabled[PATH_MAX];
    module_file_path(disabled, PATH_MAX, entry_name, "disable");

    if (access(disabled, F_OK) == 0) continue;

    /* INFO: A module marked for removal is on its way out at the next reboot;
              handing its libraries to new processes until then is not wanted,
              and the standard module path already treats "remove" this way. */
    char removed[PATH_MAX];
    module_file_path(removed, PATH_MAX, entry_name, "remove");

    if (access(removed, F_OK) == 0) continue;

    char zn_file[PATH_MAX];
    module_file_path(zn_file, PATH_MAX, entry_name, "zn_modules.txt");

    /* INFO: No access() probe here: zn_parse_cache_get stats the file and
              fopen fails the same way when it exists but is unreadable, so
              the extra syscall per module per fork bought nothing. */
    struct zn_cached_module *cached = zn_parse_cache_get(entry_name, module_dir, zn_file);
    if (cached == NULL || !cached->valid) continue;

    lists_valid++;

    for (size_t row = 0; row < cached->lines_len; row++) {
      struct zn_cached_line *line = &cached->lines[row];

      rows_examined++;

      if (!zn_matches_target(line->target, line->is_name, process_name, process_path, image_path)) {
        if (example_target == NULL) example_target = line->target;

        continue;
      }

      rows_matched++;

      /* INFO: Stated before anything is built for it, so a library that turns
                out to be a duplicate costs one stat rather than a copy of
                itself. */
      struct stat library_st;
      if (stat(line->lib_path, &library_st) == -1) {
        LOGE("Failed stating the Zygisk Next library \"%s\"", line->lib_path);

        continue;
      }

      bool already_served = false;

      for (size_t seen = 0; seen < served_len; seen++) {
        if (served[seen].dev == library_st.st_dev && served[seen].inode == library_st.st_ino) {
          already_served = true;

          break;
        }
      }

      if (already_served) continue;

      bool shared = false;
      int fd = create_library_fd(line->lib_path, &shared);
      if (fd == -1) {
        LOGE("Failed handing over the Zygisk Next library \"%s\"", line->lib_path);

        continue;
      }

      if (*out_len == capacity) {
        size_t new_capacity = capacity == 0 ? 8 : capacity * 2;

        struct ZnModuleFile *tmp = realloc(*out, new_capacity * sizeof(struct ZnModuleFile));
        if (tmp == NULL) {
          LOGE("Failed growing the Zygisk Next module list");

          if (!shared) close(fd);

          break;
        }

        *out = tmp;
        capacity = new_capacity;
      }

      char *lib_path_copy = strdup(line->lib_path);
      if (lib_path_copy == NULL) {
        LOGE("Failed copying the Zygisk Next library path \"%s\"", line->lib_path);

        if (!shared) close(fd);

        continue;
      }

      char *module_id_copy = strdup(entry_name);
      if (module_id_copy == NULL) {
        LOGE("Failed copying the Zygisk Next module id \"%s\"", entry_name);

        free(lib_path_copy);

        if (!shared) close(fd);

        continue;
      }

      (*out)[*out_len].lib_path = lib_path_copy;
      (*out)[*out_len].module_id = module_id_copy;
      (*out)[*out_len].companion = line->companion;
      (*out)[*out_len].fd = fd;
      (*out)[*out_len].owned = !shared;
      (*out_len)++;

      if (served_len < ZN_PLAN_DEDUP_MAX) {
        served[served_len].dev = library_st.st_dev;
        served[served_len].inode = library_st.st_ino;
        served_len++;
      }
    }
  }

  /* INFO: One line, and only when the object it describes is empty and there
           was something that could have filled it: a process no manifest names
           is the common case and this runs on every fork, while an empty plan
           that had material behind it is the one worth reading. The counters are
           read by the condition and not only by the log line on purpose - a
           release build compiles every LOG* out entirely, which would leave them
           set but unused, and -Werror is on. */
  if (*out_len == 0 && rows_matched == 0 && dirs_walked > 0 && lists_valid > 0 && rows_examined > 0) {
    LOGW("Zygisk Next: no library for \"%s\" - nothing of %zu row(s) in %zu list(s) named it, %zu dir(s) walked",
         process_name, rows_examined, lists_valid, dirs_walked);
  }

  /* INFO: Written for the same reason the line above is logged, and for the
            case the log cannot reach: a release build has no log at all. */
  if ((image_path != NULL && image_path[0] != '\0') || zn_process_is_zygote_class(process_name)) {
    zn_status_record(process_name, dirs_walked, lists_valid, rows_examined, rows_matched, example_target);
  }

  return true;
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
  uint32_t modules_len = (uint32_t)context->zn_len;
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

  for (size_t i = 0; i < context->zn_len; i++) {
    send_zn_module_info(&context->zn_modules[i]);
  }
}

/* INFO: The ceiling of the reload snapshot: more modules than this are
           beyond any install this serves, and the reload keeps what it has
           rather than growing the stack further. */
#define RELOAD_SNAPSHOT_MAX 512

/* INFO: Re-reads the modules directory without moving a live index.

         Zygotes and WebView hosts that already read the module list hold
         indices into context->modules, and the RemoveModule tombstone exists
         precisely to keep those stable. A rebuild-from-scratch threw that
         away: after a zygote restart reordered the list, a companion or
         module-dir request from a still-running process landed on whatever
         module now sat at its index.

         So the reload merges instead of replacing: slots for modules that
         are gone are tombstoned where they sit, slots for modules that
         stayed are refreshed in place (their library descriptor re-opened
         from the new file), and modules that are new are appended. The
         Zygisk Next list is rebuilt freely - it is keyed by name on both
         sides of the protocol, never by position. */
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

  /* INFO: The Zygisk Next list is name-keyed on both sides of the protocol,
            so it is rebuilt the plain way - out with the old, in with what
            load_modules finds, companions released with it. */
  for (size_t i = 0; i < context->zn_len; i++) {
    free(context->zn_modules[i].name);

    for (size_t j = 0; j < context->zn_modules[i].targets_len; j++) {
      free(context->zn_modules[i].targets[j]);
    }

    free(context->zn_modules[i].targets);
  }

  free(context->zn_modules);
  context->zn_modules = NULL;
  context->zn_len = 0;

  free_zn_companions(context);
  zn_parse_cache_clear();

  DIR *zn_dir = opendir(ZYGISK_MODULES_DIR);
  if (zn_dir == NULL) {
    LOGE("Failed opening modules directory: %s.", ZYGISK_MODULES_DIR);

    send_daemon_info(context);

    return;
  }

  struct dirent *entry;
  while ((entry = readdir(zn_dir)) != NULL) {
    if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN) continue;
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, "rezygisk") == 0) continue;

    char zn_modules[PATH_MAX];
    module_file_path(zn_modules, PATH_MAX, entry->d_name, "zn_modules.txt");
    if (access(zn_modules, F_OK) != 0) continue;

    if (!add_zn_module(context, entry->d_name)) {
      LOGE("Failed to record the Zygisk Next module \"%s\"", entry->d_name);
    }
  }

  closedir(zn_dir);

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

  /* INFO: The Zygisk Next set only changes on a module load or reload, so
            the load-time answer rides along for free; the loader remembers
            it and skips its per-fork ReadZnModules when there is nothing to
            resolve. A module installed while the daemon runs is picked up on
            the next reload - flashing a module comes with a reboot anyway. */
  if (client->context->zn_len > 0) {
    flags |= PROCESS_ZN_PRESENT;
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

static void handle_spawn_zn_companion(struct Client *client) {
  char lib_path[PATH_MAX];
  ssize_t ret = read_string(client->fd, lib_path, sizeof(lib_path));
  if (ret <= 0) {
    LOGE("Failed reading the Zygisk Next library path.");

    return;
  }

  /* INFO: One companion per library instead of one per request: the process
             and its dlopened library are kept for the daemon's lifetime, a
             restarted zygote or a newly forked app reuses it, and the
             per-process fork storm of the per-request model disappears. A
             dead companion is detected here and respawned on demand. */
  for (size_t i = 0; i < client->context->zn_companions_len; i++) {
    struct ZnCompanion *companion = &client->context->zn_companions[i];

    if (strcmp(companion->lib_path, lib_path) != 0) continue;

    if (check_unix_socket(companion->fd, false)) {
      LOGD("Reusing the Zygisk Next companion of \"%s\"", lib_path);

      ret = write_uint8_t(client->fd, (uint8_t)1);
      ASSURE_SIZE_WRITE("SpawnZnCompanion", "response", ret, sizeof(uint8_t), return);

      if (write_fd(client->fd, companion->fd) == -1) LOGE("Failed sending the Zygisk Next companion fd.");

      return;
    }

    LOGI("The Zygisk Next companion of \"%s\" is gone, respawning", lib_path);

    release_zn_companion_fd(companion->fd);
    free(companion->lib_path);

    memmove(&client->context->zn_companions[i], &client->context->zn_companions[i + 1],
            (client->context->zn_companions_len - i - 1) * sizeof(struct ZnCompanion));
    client->context->zn_companions_len--;

    break;
  }

  int companion_fd = spawn_zn_companion(client->argv, lib_path);
  if (companion_fd < 0) {
    LOGE("Failed spawning the Zygisk Next companion of \"%s\"", lib_path);

    ret = write_uint8_t(client->fd, (uint8_t)0);
    ASSURE_SIZE_WRITE("SpawnZnCompanion", "response", ret, sizeof(uint8_t), return);

    return;
  }

  LOGI("Spawned the Zygisk Next companion of \"%s\"", lib_path);

  /* INFO: The socket belongs to the context from here on; serving this
             client only duplicates it. If the bookkeeping cannot keep up,
             the healthy companion still serves this one client untracked. */
  struct ZnCompanion *tmp = realloc(client->context->zn_companions,
                                    (client->context->zn_companions_len + 1) * sizeof(struct ZnCompanion));
  if (tmp == NULL) {
    LOGW("Failed tracking the Zygisk Next companion of \"%s\"", lib_path);

    ret = write_uint8_t(client->fd, (uint8_t)1);
    ASSURE_SIZE_WRITE("SpawnZnCompanion", "response", ret, sizeof(uint8_t), return);

    if (write_fd(client->fd, companion_fd) == -1) LOGE("Failed sending the Zygisk Next companion fd.");

    close(companion_fd);

    return;
  }

  /* INFO: The block may have moved, so the context takes the new pointer before
            anything below can fail. Leaving it on the old one after a later
            failure would hand the next request a pointer realloc has already
            freed - the loop at the top of this function and free_zn_companions()
            both walk that array. */
  client->context->zn_companions = tmp;

  char *lib_path_copy = strdup(lib_path);
  if (lib_path_copy == NULL) {
    LOGW("Failed tracking the Zygisk Next companion of \"%s\"", lib_path);

    ret = write_uint8_t(client->fd, (uint8_t)1);
    ASSURE_SIZE_WRITE("SpawnZnCompanion", "response", ret, sizeof(uint8_t), return);

    if (write_fd(client->fd, companion_fd) == -1) LOGE("Failed sending the Zygisk Next companion fd.");

    close(companion_fd);

    return;
  }

  client->context->zn_companions[client->context->zn_companions_len].lib_path = lib_path_copy;
  client->context->zn_companions[client->context->zn_companions_len].fd = companion_fd;
  client->context->zn_companions_len++;

  ret = write_uint8_t(client->fd, (uint8_t)1);
  ASSURE_SIZE_WRITE("SpawnZnCompanion", "response", ret, sizeof(uint8_t), return);

  if (write_fd(client->fd, companion_fd) == -1) LOGE("Failed sending the Zygisk Next companion fd.");
}

static void handle_read_zn_modules(struct Client *client) {
  char process_name[PROCESS_NAME_MAX_LEN];
  ssize_t ret = read_string(client->fd, process_name, sizeof(process_name));
  if (ret <= 0) {
    LOGE("Failed reading the process name for ReadZnModules.");

    return;
  }

  char process_path[PATH_MAX];
  ret = read_string(client->fd, process_path, sizeof(process_path));
  if (ret <= 0) {
    LOGE("Failed reading the process path for ReadZnModules.");

    return;
  }

  /* INFO: The path of the HyperOS runtime image, from the process that hosts
            one. Empty for everything else, including an application the spawner
            forked: it inherits the runtime state, and inheriting it is not the
            same as being the spawner.

            An empty string is a valid answer here and not a failure, which is
            why this one test is `ret < 0` where the name and the path above use
            `ret <= 0`: read_string answers 0 for a string of length zero, and
            refusing that would hang up on every request from a process that is
            not the runtime host - which is all of them, the zygote and the apps
            included. The plan would come back empty everywhere and no Zygisk
            Next module would load anywhere, with nothing in any log to say
            why. The name and the path cannot legitimately be empty, so refusing
            those stays the right answer. */
  char image_path[PATH_MAX] = { 0 };
  ret = read_string(client->fd, image_path, sizeof(image_path));
  if (ret < 0) {
    LOGE("Failed reading the runtime image path for ReadZnModules.");

    return;
  }

  struct ZnModuleFile *files = NULL;
  size_t files_len = 0;

  if (!collect_zn_modules(process_name, process_path, image_path, &files, &files_len)) {
    ret = write_size_t(client->fd, 0);
    ASSURE_SIZE_WRITE("ReadZnModules", "len", ret, sizeof(uint32_t), return);

    return;
  }

  ret = write_size_t(client->fd, files_len);
  if (ret != (ssize_t)sizeof(uint32_t)) {
    LOGE("Failed writing the Zygisk Next module count.");

    free_zn_module_files(files, files_len);

    return;
  }

  LOGD("Serving %zu Zygisk Next module(s) to \"%s\"", files_len, process_name);

  for (size_t i = 0; i < files_len; i++) {
    if (write_string(client->fd, files[i].lib_path) == -1) {
      LOGE("Failed writing a Zygisk Next module path.");

      break;
    }

    /* INFO: The module id follows its library, so the two names of one module
              arrive together: the loader keys its entry on the path and reports
              it back by the id. */
    if (write_string(client->fd, files[i].module_id) == -1) {
      LOGE("Failed writing a Zygisk Next module id.");

      break;
    }

    ret = write_uint8_t(client->fd, (uint8_t)(files[i].companion ? 1 : 0));
    if (ret != (ssize_t)sizeof(uint8_t)) {
      LOGE("Failed writing a Zygisk Next companion flag.");

      break;
    }

    if (write_fd(client->fd, files[i].fd) == -1) {
      LOGE("Failed sending a Zygisk Next module fd.");

      break;
    }
  }

  free_zn_module_files(files, files_len);
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

/* INFO: Takes an accepted connection over as a HyperOS runtime control session.

         This is the one action that answers without giving the connection back.
         The runtime reports over it later, from processes that cannot open one
         of their own by then - an application is specialized, and the daemon's
         socket is not its to connect to - so the descriptor is kept here and the
         process that asked for it is expected to fork with it open. What the
         loop below watches, therefore, is not a request that is still running
         but a session that has not ended.

         The caller is not checked against anything: a session grants nothing
         but the ability to say that a module was told about a specialization,
         and every process that can reach this socket already runs as root. */
static void handle_open_zn_control_session(struct Client *client) {
  struct Context *context = client->context;

  if (context->zn_sessions_len == context->zn_sessions_capacity) {
    const size_t capacity = context->zn_sessions_capacity == 0
                              ? (size_t)8
                              : context->zn_sessions_capacity * 2;

    int *grown = realloc(context->zn_sessions, capacity * sizeof(int));
    if (grown == NULL) {
      /* INFO: Nothing is confirmed and the connection is left to be closed: a
                session the loop is not watching is worse than no session, because
                the process that asked for it would keep writing records nobody
                reads until one of them no longer fit the socket. */
      LOGE("Failed growing the Zygisk Next control session list.");

      return;
    }

    context->zn_sessions = grown;
    context->zn_sessions_capacity = capacity;
  }

  context->zn_sessions[context->zn_sessions_len] = client->fd;
  context->zn_sessions_len++;

  /* INFO: A session is read while it is quiet and reports whenever the process
            behind it specializes, which can be minutes later. The exchange
            budget that bounds every request would end it at the first quiet
            moment - but no deadline at all is worse than a generous one:
            the descriptor is inherited by every application the spawner
            forks, and any of them can write half a record and stop. A read
            that can never time out then blocks the daemon's poll loop
            forever, and every loader request behind it burns its own budget
            against a daemon that stopped answering.

            A real report is one sendmsg - the writer sends the record whole
            or nothing - so the fields are already in the socket buffer when
            poll wakes this side. Anything still split after this long is
            not a report arriving slowly, and ending the session is the
            right answer to it. */
  struct timeval timeout = { .tv_sec = ZN_SESSION_READ_TIMEOUT_SECS, .tv_usec = 0 };
  setsockopt(client->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(client->fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  /* INFO: The loop closes every accepted connection it is not told to keep. */
  client->keep_open = true;

  /* INFO: Confirmed last, and only once there is a session to confirm: the
            answer is what tells the caller this descriptor is worth keeping, and
            one sent before the list held it would be a promise this side cannot
            keep. A failure here is taken back out of the list and left to the
            loop to close - one close for one descriptor. */
  ssize_t ret = write_uint8_t(client->fd, 1);
  if (ret != (ssize_t)sizeof(uint8_t)) {
    LOGE("Failed confirming a Zygisk Next control session.");

    context->zn_sessions_len--;
    client->keep_open = false;

    return;
  }

  LOGI("Opened a Zygisk Next control session (%zu open)", context->zn_sessions_len);
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
  { RemoveModule,           "RemoveModule",           handle_remove_module           },
  { ReadZnModules,          "ReadZnModules",          handle_read_zn_modules         },
  { SpawnZnCompanion,       "SpawnZnCompanion",       handle_spawn_zn_companion      },
  { OpenZnControlSession,   "OpenZnControlSession",   handle_open_zn_control_session }
};

/* INFO: ReportZnRuntime is deliberately not in the table. It is a record on an
         already open session, not an action a client opens a connection to ask
         for, and the only thing a listener could do with it is refuse it - which
         is what an unregistered action gets. */

static const struct ActionHandler *find_action_handler(enum DaemonSocketAction action) {
  for (size_t i = 0; i < sizeof(kActionHandlers) / sizeof(kActionHandlers[0]); i++) {
    if (kActionHandlers[i].action == action) return &kActionHandlers[i];
  }

  return NULL;
}

/* INFO: Reads one record from a control session. Everything the runtime reports
         is a report: this is a channel one way, opened by the spawner and
         written by the applications it forks, and none of them is waiting for
         anything to come back.

         Returns false when the session is over. Three readings mean that, and
         they are deliberately one answer: the last process holding the session
         exited (end of file), the record is not one this build knows, or it did
         not arrive whole. A stream this build cannot parse is not one it can
         stay in step with - the alternative is reading the next record at the
         wrong offset and reporting whatever is found there. */
static bool serve_zn_session(struct Context *restrict context, size_t index) {
  const int fd = context->zn_sessions[index];

  uint8_t action8 = 0;
  ssize_t len = read_uint8_t(fd, &action8);
  if (len <= 0) return false;

  if (action8 != (uint8_t)ReportZnRuntime) {
    LOGW("Unknown record %u on a Zygisk Next control session, ending it", (unsigned int)action8);

    return false;
  }

  /* INFO: The record is read field for field, and the fields are the two that
            zn_control_protocol.h declares - the one place that says what shape a
            writer sends and a reader expects. Reading it as a structure would
            work right up until one side's compiler laid it out differently.

            The pid is the one the reporter sent rather than the peer credential
            of this socket: the session was opened by the spawner, so the peer is
            the spawner for every report its children make, and a line that named
            it would name the wrong process. */
  uint32_t pid = 0;
  uint32_t id_len = 0;

  if (read_uint32_t(fd, &pid) == -1) return false;
  if (read_uint32_t(fd, &id_len) == -1) return false;

  /* INFO: A report that names no process is not a report, and neither is one
            whose length cannot be a module id - both mean this stream is no
            longer where this build thinks it is, and the next record would be
            read at the wrong offset. */
  if (pid == 0 || id_len == 0 || id_len >= ZN_CONTROL_MODULE_ID_MAX) {
    LOGW("Malformed record on a Zygisk Next control session (pid %u, id length %u), ending it", pid, id_len);

    return false;
  }

  char module_id[ZN_CONTROL_MODULE_ID_MAX];
  if (read_loop(fd, module_id, id_len) != (ssize_t)id_len) return false;

  module_id[id_len] = '\0';

  LOGI("HyperOS runtime: module \"%s\" was told about the specialization of pid %u", module_id, pid);

  return true;
}

/* INFO: Serves one accepted connection: the action is read, dispatched, and the
         connection closed again - unless the handler took it over, which only
         the control session does. */
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

  /* INFO: The set is rebuilt on every wakeup - the listener first, then one
            entry per live control session - but the array itself is kept: it
            grows to the high-water mark of the session and is rewritten in
            place after that. Allocating it per wakeup made this the daemon's
            most frequent allocation, and its failure the one that ended the
            loop - a daemon that returns leaves every session without one until
            the next zygote start. Sessions come and go; the peak is what the
            array has to be sized for. */
  struct pollfd *polled = NULL;
  size_t polled_capacity = 0;

  while (1) {
    const size_t session_count = context->zn_sessions_len;
    const size_t wanted = session_count + 1;

    if (wanted > polled_capacity) {
      size_t capacity = polled_capacity == 0 ? (size_t)16 : polled_capacity;

      while (capacity < wanted) capacity *= 2;

      struct pollfd *grown = realloc(polled, capacity * sizeof(struct pollfd));
      if (grown == NULL) {
        PLOGE("grow the poll set");

        free(polled);

        return;
      }

      polled = grown;
      polled_capacity = capacity;
    }

    /* INFO: The listener and every control session are waited on together. A
              spawner forks an application per launch and opens a session per
              fork, so there can be many of them at once, and waiting on any one
              of them alone would leave the listener unserved for as long as that
              one is quiet - while the requests behind it are zygotes about to
              specialize, where a wait is felt by the user. */
    polled[0].fd = socket_fd;
    polled[0].events = POLLIN;
    polled[0].revents = 0;

    for (size_t i = 0; i < session_count; i++) {
      polled[i + 1].fd = context->zn_sessions[i];
      polled[i + 1].events = POLLIN;
      polled[i + 1].revents = 0;
    }

    const int ready = poll(polled, (nfds_t)wanted, -1);
    if (ready == -1) {
      /* A signal (EINTR) only interrupts this one wait; keep serving. */
      if (errno == EINTR) continue;

      PLOGE("poll");

      free(polled);

      return;
    }

    const bool listener_ready = (polled[0].revents & POLLIN) != 0;

    /* INFO: The sessions are read first and walked backwards, so that one
              ending here cannot move the index of one that has not been read
              yet: dropping the entry at i shifts everything after it left, and
              those have already been served by then. */
    for (size_t i = session_count; i > 0; i--) {
      if (polled[i].revents == 0) continue;

      if (serve_zn_session(context, i - 1)) continue;

      close(context->zn_sessions[i - 1]);

      memmove(&context->zn_sessions[i - 1], &context->zn_sessions[i],
              (context->zn_sessions_len - i) * sizeof(int));
      context->zn_sessions_len--;
    }

    if (!listener_ready) continue;

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

      free(polled);

      return;
    }

    serve_accepted(client_fd, context, argv, &first_process);
  }
}

/* INFO: Ends every control session that is still open.

         Only the end of the daemon does this. A session belongs to the process
         that opened it and to the applications it was passed to; ending one
         because the daemon was asked for something - a zygote restart is the one
         request that reloads the module list - would take the runtime's
         reporting away from applications that are still running. */
static void free_zn_sessions(struct Context *restrict context) {
  for (size_t i = 0; i < context->zn_sessions_len; i++) {
    close(context->zn_sessions[i]);
  }

  free(context->zn_sessions);

  context->zn_sessions = NULL;
  context->zn_sessions_len = 0;
  context->zn_sessions_capacity = 0;
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
  free_zn_sessions(&context);
  free_modules(&context);
  root_impl_cleanup();
}
