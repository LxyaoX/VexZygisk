#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>

#include <android/dlext.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "daemon.h"
#include "logging.h"
#include "misc.h"
#include "zygisk_paths.h"

#include "zn_api.h"
#include "zn_loader.h"

/* INFO: The command byte and the control buffer live in the shared protocol
         header: the daemon side runs the same loop off the same contract. */
#include "zn_companion_protocol.h"

/* INFO: Only the daemon opens module libraries now, so the loader never names
         the modules directory itself. */
#define ZN_MAX_MODULES 32

/* INFO: One loaded module, and the self handle its callbacks were given.

         What is kept is what is used: the module id names the module in a
         registration report, the path is what the duplicate check compares, and
         the companion descriptor is what connectCompanion hands a socket from.
         The target is not kept because nothing asks for it - the daemon did the
         matching, and the handle is opaque to the module that receives it. */
struct zn_entry {
  bool companion;
  char *module_id;
  char *lib_path;
  int companion_fd;
};

/* INFO: Loaded libraries are kept for the whole life of the process, a module
         is never unloaded once its callbacks are installed. The entries are
         handed to the modules as their self handle, so they must outlive the
         scan that produced them. */
static void *loaded_libs[ZN_MAX_MODULES];
static struct zn_entry loaded_entries[ZN_MAX_MODULES];
static size_t loaded_libs_count = 0;

/* The module library is loaded from a descriptor the daemon opened and passed
   over SCM_RIGHTS: the only mode that works for a target which cannot read
   /data/adb itself, which is every process outside the zygote's domain. */
static void *dlopen_from_fd(int fd, const char *name, int flags) {
  android_dlextinfo info = { 0 };
  info.flags = ANDROID_DLEXT_USE_LIBRARY_FD | ANDROID_DLEXT_FORCE_LOAD;
  info.library_fd = fd;

  /* INFO: The basename is tried first and the whole path second, which is the
            reference's order: the name handed to the linker is the one the
            library is known by inside this process, and a soname keeps the
            soinfo and the maps listing tidy. FORCE_LOAD asks for a fresh load
            rather than a second handle to one already loaded - and the
            duplicate check in this file is what stops that from initialising a
            module twice. */
  const char *slash = strrchr(name, '/');
  const char *base = slash == NULL ? name : slash + 1;

  void *lib = android_dlopen_ext(base, flags, &info);
  if (lib == NULL) lib = android_dlopen_ext(name, flags, &info);
  if (lib == NULL) LOGE("dlopen %s from fd %d failed: %s", name, fd, dlerror());

  return lib;
}

static char *read_process_path(void) {
  char buf[PATH_MAX];
  if (read_exe_path((int)getpid(), buf, sizeof(buf)) <= 0) return NULL;

  return strdup(buf);
}

static char *get_process_name(const char *process_path) {
  if (process_path == NULL) return NULL;

  const char *last_slash = strrchr(process_path, '/');

  return (char *)(last_slash == NULL ? process_path : last_slash + 1);
}

/* Asks the daemon to fork a companion for the module and hands its end back.

   The companion is not forked here: the child would inherit this process's
   domain, which in an application is a restricted app domain, and a companion
   started there cannot read the module it is meant to serve. */
static int spawn_companion(const char *lib_path) {
  return rezygiskd_spawn_zn_companion(lib_path);
}

/* INFO: Failure symmetry, reviewed: every branch that gives up after a
         successful dlopen releases the handle with dlclose and closes the
         handed-over module_fd. Past onModuleLoaded the library is
         deliberately left loaded for the life of the process. */
static bool load_entry(struct zn_entry *entry, void **lib_handle, int module_fd) {
  /* INFO: Loaded from the descriptor the daemon opened, which is the only way
           this works for a process that cannot read /data/adb itself. The
           descriptor stays open for the life of the library; bionic does not
           take ownership of a USE_LIBRARY_FD one.

           A caller with no descriptor must not fall back to opening the path:
           the reference skips such an entry outright rather than reaching for
           the filesystem, and the target it would read from is exactly the one
           that has no business reading it. */
  void *lib = dlopen_from_fd(module_fd, entry->lib_path, RTLD_NOW);
  if (lib == NULL) {
    LOGE("Failed loading the Zygisk Next library [%s] from its fd", entry->lib_path);

    close(module_fd);

    return false;
  }

  struct ZygiskNextModule *module = (struct ZygiskNextModule *)dlsym(lib, "zn_module");
  if (module == NULL) {
    /* INFO: Not worth an error: a module may ship a zn_modules.txt and still
             only speak the standard Zygisk contract, LSPosed being the common
             case. It is then loaded by the standard path, which runs its
             zygisk_module_entry. */
    LOGW("The library [%s] does not export zn_module, it is not a Zygisk Next module", entry->lib_path);

    dlclose(lib);
    if (module_fd >= 0) close(module_fd);

    return false;
  }

  /* INFO: The version the module was built against is what decides whether it
            can be served at all, and the answer is taken from the ends: a
            module newer than this build describes a table this build does not
            have, and one older than the two contracts this fork serves describes
            a table whose entries have moved - both would be read at the wrong
            offsets. ZN_MODULE_API_MIN and zn_api.h say where the line is and
            why it is drawn there. */
  if (module->target_api_version < ZN_MODULE_API_MIN || module->target_api_version > ZYGISK_NEXT_API_VERSION) {
    LOGW("The module [%s] targets Zygisk Next API version %d, this build serves %d to %d",
         entry->lib_path, module->target_api_version, ZN_MODULE_API_MIN, ZYGISK_NEXT_API_VERSION);

    dlclose(lib);
    if (module_fd >= 0) close(module_fd);

    return false;
  }

  if (module->onModuleLoaded == NULL) {
    LOGE("The library [%s] exports zn_module without an onModuleLoaded callback", entry->lib_path);

    dlclose(lib);
    if (module_fd >= 0) close(module_fd);

    return false;
  }

  /* INFO: Companions only exist from API v3 onwards. */
  if (entry->companion) {
    if (module->target_api_version >= 3) {
      entry->companion_fd = spawn_companion(entry->lib_path);
    } else {
      LOGW("The module [%s] declares a companion but targets API %d (< 3), skipping it", entry->lib_path, module->target_api_version);
    }
  }

  LOGD("Loading the Zygisk Next module [%s] of [%s]", entry->lib_path, entry->module_id);

  /* INFO: From here on the library stays loaded for the life of the process:
             its callbacks and hooks outlive this call, unloading is not an
             option. */
  *lib_handle = lib;

  module->onModuleLoaded((void *)entry, zn_get_api());

  return true;
}

/* INFO: Asks the companion behind `handle` for a fresh connection and returns
         its socket, or -1 when the module has no reachable companion. */
int zn_companion_connect(void *handle) {
  if (handle == NULL) return -1;

  struct zn_entry *entry = (struct zn_entry *)handle;
  if (entry->companion_fd < 0) return -1;

  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) {
    LOGE("Failed creating the companion connection: %s", strerror(errno));

    return -1;
  }

  uint8_t command = ZN_COMPANION_CMD_CONNECT;
  union zn_cmsg_buffer buffer;

  struct iovec io;
  io.iov_base = &command;
  io.iov_len = sizeof(command);

  struct msghdr message;
  memset(&message, 0, sizeof(message));
  message.msg_iov = &io;
  message.msg_iovlen = 1;
  message.msg_control = buffer.control;
  message.msg_controllen = sizeof(buffer.control);

  struct cmsghdr *header = CMSG_FIRSTHDR(&message);
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(header), &sockets[1], sizeof(sockets[1]));

  /* INFO: MSG_NOSIGNAL: the daemon-side holder of this socket can go away
          (a companion crash, a daemon restart), and SIGPIPE's default action
          would take this application down with it - this runs inside the
          module's connectCompanion(), mid-specialize. */
  if (sendmsg(entry->companion_fd, &message, MSG_NOSIGNAL) < 0) {
    LOGE("Failed requesting a companion connection: %s", strerror(errno));

    close(sockets[0]);
    close(sockets[1]);

    return -1;
  }

  close(sockets[1]);

  /* INFO: The socket is only handed over once the companion acknowledges it, so
            what the module receives is a connection the companion really holds.
            Bounded, not blocking: a companion left over from an older build
            never acknowledges, and hanging on it would turn a version skew into
            a stuck connectCompanion instead of a socket that still works. */
  struct pollfd waiting = { .fd = sockets[0], .events = POLLIN };

  int ready;
  do {
    ready = poll(&waiting, 1, ZN_COMPANION_ACK_TIMEOUT_MS);
  } while (ready == -1 && errno == EINTR);

  if (ready > 0) {
    uint8_t ack = 0;
    ssize_t got;

    do {
      got = read(sockets[0], &ack, sizeof(ack));
    } while (got == -1 && errno == EINTR);

    if (got != (ssize_t)sizeof(ack)) {
      LOGE("The companion did not acknowledge the connection (read returned %zd)", got);

      close(sockets[0]);

      return -1;
    }

    if (ack != ZN_COMPANION_ACK) {
      LOGE("The companion answered with %u instead of an acknowledgement", (unsigned)ack);

      close(sockets[0]);

      return -1;
    }
  } else if (ready == 0) {
    LOGW("The companion did not acknowledge within %d ms, using the connection anyway", ZN_COMPANION_ACK_TIMEOUT_MS);
  } else {
    LOGE("Failed waiting for the companion acknowledgement: %s", strerror(errno));

    close(sockets[0]);

    return -1;
  }

  return sockets[0];
}

/* INFO: A library that was already loaded — usually one inherited from the
         zygote when this process was forked — must not be dlopened a second
         time: its hooks would be installed twice. */
static bool zn_already_loaded(const char *lib_path) {
  for (size_t i = 0; i < loaded_libs_count; i++) {
    if (loaded_entries[i].lib_path != NULL && strcmp(loaded_entries[i].lib_path, lib_path) == 0) return true;
  }

  return false;
}

/* INFO: Loads the libraries the daemon resolved for this process. It is the
         only path that works for a target which cannot read /data/adb/modules,
         since the daemon opens every file on its behalf. An empty answer is a
         valid answer: a target the daemon has no entry for loads nothing, which
         is also the answer the reference gives. */
static void load_modules_from_daemon(const char *process_name, const char *process_path, uint8_t connect_retry, uint32_t connect_delay_us) {
  struct zn_module_file *files = NULL;
  size_t files_len = 0;

  if (!rezygiskd_read_zn_modules(process_name, process_path, connect_retry, connect_delay_us, &files, &files_len)) return;

  LOGD("Got %zu Zygisk Next module(s) from VexZygiskd", files_len);

  for (size_t i = 0; i < files_len; i++) {
    if (loaded_libs_count >= ZN_MAX_MODULES) {
      LOGW("Reached the limit of %d Zygisk Next modules, skipping \"%s\"", ZN_MAX_MODULES, files[i].lib_path);

      break;
    }

    if (zn_already_loaded(files[i].lib_path)) {
      LOGD("Zygisk Next module \"%s\" is already loaded, skipping", files[i].lib_path);

      continue;
    }

    struct zn_entry *entry = &loaded_entries[loaded_libs_count];
    entry->companion = files[i].companion;
    entry->module_id = strdup(files[i].module_id);
    entry->lib_path = strdup(files[i].lib_path);
    entry->companion_fd = -1;

    if (entry->module_id == NULL || entry->lib_path == NULL) {
      LOGE("Failed copying the Zygisk Next module \"%s\"", files[i].lib_path);

      free(entry->module_id);
      free(entry->lib_path);

      entry->module_id = NULL;
      entry->lib_path = NULL;
      entry->companion_fd = -1;

      break;
    }

    /* INFO: load_entry takes over the descriptor: a loaded library keeps it
             for its whole life (bionic does not own USE_LIBRARY_FD fds), and a
             failed one closes it on the spot. Handing it over here, instead of
             letting free_zn_module_files close everything, keeps a loaded
             library's descriptor alive and avoids a double close on failure. */
    int module_fd = files[i].fd;
    files[i].fd = -1;

    if (load_entry(entry, &loaded_libs[loaded_libs_count], module_fd)) {
      loaded_libs_count++;

      continue;
    }

    if (entry->companion_fd >= 0) close(entry->companion_fd);

    free(entry->module_id);
    free(entry->lib_path);

    /* INFO: The slot is free again, so leave it as "no companion" rather than
             a zeroed struct whose fd would read as a valid descriptor. */
    entry->module_id = NULL;
    entry->lib_path = NULL;
    entry->companion_fd = -1;
  }

  free_zn_module_files(files, files_len);
}

/* INFO: Loads every Zygisk Next library whose target matches process_name.
         process_path always comes from /proc/self/exe: a path= target selects
         the zygote binary, which is the executable of every process this
         loader runs in, exactly as Zygisk Next treats it.

         This runs once in the zygote itself, and once more in every forked
         child with that child's own process name — without the second call,
         per-application targets (name=com.foo) would never match anywhere.

         The daemon is the only source of the module plan, so a target that
         reaches here while the daemon is down loads no module at all. That is
         why a caller whose load is one-shot for a whole process tree passes a
         connection window measured in seconds, and why an ordinary one still
         keeps the short spacing it can afford; zn_loader.h states the same
         contract for those callers. */
bool zn_injected_target = false;

void zn_load_all_modules(uint8_t connect_retry, uint32_t connect_delay_us) {
  /* INFO: This process is a target: the loader runs in it because the monitor
            injected it here, and the modules it is about to load are mapped into
            it as they load. */
  zn_injected_target = true;

  char *process_path = read_process_path();
  if (process_path == NULL) {
    LOGE("Failed resolving the current process path");

    return;
  }

  const char *process_name = get_process_name(process_path);

  load_modules_from_daemon(process_name, process_path, connect_retry, connect_delay_us);

  free(process_path);
}

void zn_load_modules_for_process(const char *process_name) {
  if (process_name == NULL) return;

  char *process_path = read_process_path();
  if (process_path == NULL) {
    LOGE("Failed resolving the current process path");

    return;
  }

  load_modules_from_daemon(process_name, process_path, 1, REZYGISKD_RETRY_DELAY_US);

  free(process_path);
}

size_t zn_loaded_library_count(void) {
  return loaded_libs_count;
}
