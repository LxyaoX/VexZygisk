#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "logging.h"
#include "misc.h"
#include "zn_lsplt.h"

#include "zn_hyos.h"

/* INFO: The layout of every table and structure this file builds or reads is
         pinned in zn_hyos.h, next to the contract it belongs to. */

/* INFO: The HyperOS runtime, as the contract describes it.

         The image is found in the process maps: on HyperOS the process hosting
         the runtime is not always the file /proc/self/exe names - it can be an
         app_process binary with the spawner image mapped into it - so the
         mapping is what identifies it, and the bytes behind the mapping are
         what confirm it. zn_spawner.h carries both predicates.

         Once found, the hooks the runtime needs are installed in that image
         through its PLT: a GOT entry always exists and is always writable,
         while rewriting the spawner's code for an inline hook can be refused by
         the policy it runs under. They are:
           - fork, so a child can be told apart from the spawner and given a
             control session of its own before it runs;
           - selinux_android_setcontext, which every specialization of a forked
             application goes through and which carries the three strings the
             contract promises the modules.
         A raw clone() would run none of them, which is why the runtime is armed
         only when both symbols are really hooked, and why nothing is left armed
         when they are not. */

typedef pid_t (*zn_hyos_fork_fn)(void);
typedef int (*zn_hyos_setcontext_fn)(uid_t uid, int is_system_server, const char *se_info, const char *package_name);

/* INFO: One registered module. The id is borrowed from the loader's module
         table, which outlives every callback it can produce, so the runtime
         neither copies nor owns it. It is NULL for a registration made outside
         onModuleLoaded - the contract does not ask for one, and nothing stops a
         module from making it - and such a registration is served as usual and
         simply not reported. */
struct zn_hyos_registration {
  struct ZygiskNextHyosModule module;
  const char *module_id;
};

static struct zn_hyos_registration *zn_hyos_registrations = NULL;
static size_t zn_hyos_registration_count = 0;
static size_t zn_hyos_registration_capacity = 0;

/* INFO: Whether this process hosts the runtime, and whether a module may still
         register. The window is open from initialize() until the hooks are
         installed; a module registers while it is being loaded, which is the
         only moment the contract names. */
static bool zn_hyos_available = false;
static bool zn_hyos_registration_open = false;
static bool zn_hyos_hooks_ready = false;

/* INFO: File identity of the spawner image, which is how LSPlt names a library
         to hook. */
static dev_t zn_hyos_target_dev = 0;
static ino_t zn_hyos_target_inode = 0;

static zn_hyos_open_session_fn zn_hyos_open_session = NULL;
static zn_hyos_report_fn zn_hyos_report = NULL;
static const char *zn_hyos_registering_id = NULL;

static zn_hyos_fork_fn zn_hyos_original_fork = NULL;
static zn_hyos_setcontext_fn zn_hyos_original_setcontext = NULL;

/* INFO: The state of the forked application, all of it inherited from the
         spawner at fork and then owned by this process alone: the session it
         reports over, whether that session is usable, and the three strings the
         specialization is described by.

         `dispatched` is what makes the callback fire once. A specialization
         runs selinux_android_setcontext once, but the guarantee the contract
         makes is about the module, not about the caller, so it is held here
         rather than assumed. */
static int zn_hyos_child_session_fd = -1;
static bool zn_hyos_child_ready = false;
static bool zn_hyos_child_dispatched = false;

/* INFO: Whether this process was forked by the spawner, whatever became of the
         session it was handed. The two are separate questions on purpose: a
         child whose session could not be opened is still an application, and
         still wants the answers that are about being one - the cached commit
         below all - while a child that is told is the one `child_ready`
         describes. */
static bool zn_hyos_is_child = false;

/* INFO: The path of the image the runtime was found in. Empty until a scan
            finds one, and cleared again when it does not. */
static char zn_hyos_spawner_image[PATH_MAX] = { 0 };

static char zn_hyos_process_name[ZN_HYOS_VALUE_MAX];
static char zn_hyos_package_name[ZN_HYOS_VALUE_MAX];
static char zn_hyos_se_info[ZN_HYOS_VALUE_MAX];

/* INFO: Held across the fork itself, so a second thread cannot open a session
         for the same child and leak the one it opened. A flag rather than a
         mutex because the child inherits the whole lock state: a mutex locked
         by the forking thread is still locked in the child, and only the thread
         that took it could release it - which is exactly the one that no longer
         exists in the child when it was another thread that forked. */
static atomic_flag zn_hyos_fork_lock = ATOMIC_FLAG_INIT;

struct zn_hyos_spawner_scan {
  dev_t dev;
  ino_t inode;
  uintptr_t start;
  bool found;
  /* INFO: The path the image is mapped from, copied rather than pointed at:
            the maps walk hands out a path into the line it was read from, and
            that line is gone by the time the caller needs the answer. */
  char path[PATH_MAX];
};

/* INFO: Finds the runtime image in the maps, and stops the walk as soon as it
         has.

         The two guards before the header is read are the ones that make reading
         it safe at all: the mapping has to be readable (a PROT_NONE mapping is
         in the listing, and dereferencing one is a segfault in the injected
         process), and it has to be at least a header long. Nothing here trusts
         the name - a path spelled the spawner's way is only the runtime if the
         bytes behind it are an ELF this process could run. */
static bool zn_hyos_visit_spawner(const struct map_entry *entry, void *userdata) {
  struct zn_hyos_spawner_scan *scan = (struct zn_hyos_spawner_scan *)userdata;

  if (entry->offset != 0 || entry->dev == 0 || entry->inode == 0 || entry->path == NULL) return true;
  if (!zn_spawner_map_is_spawner(entry->path)) return true;
  if ((entry->perms & PROT_READ) == 0) return true;
  if (entry->end <= entry->start) return true;
  if (!zn_spawner_elf_is_image((const unsigned char *)entry->start, (size_t)(entry->end - entry->start))) return true;

  scan->dev = entry->dev;
  scan->inode = entry->inode;
  scan->start = entry->start;

  size_t len = strip_deleted_suffix(entry->path, strlen(entry->path));
  if (len >= sizeof(scan->path)) len = sizeof(scan->path) - 1;
  memcpy(scan->path, entry->path, len);
  scan->path[len] = '\0';

  scan->found = true;

  return false;
}

bool zn_hyos_initialize(zn_hyos_open_session_fn open_session, zn_hyos_report_fn report) {
  /* INFO: Every field is reset, not only the ones this function is about: the
            question "is there a runtime here" is asked once per process, and an
            answer left over from an earlier call would be given to a module
            asking afterwards. */
  zn_hyos_available = false;
  zn_hyos_registration_open = false;
  zn_hyos_hooks_ready = false;
  zn_hyos_spawner_image[0] = '\0';
  zn_hyos_registration_count = 0;
  zn_hyos_open_session = open_session;
  zn_hyos_report = report;
  zn_hyos_registering_id = NULL;

  struct zn_hyos_spawner_scan scan = { 0 };

  if (!scan_maps_safe("self", zn_hyos_visit_spawner, &scan) || !scan.found) return false;

  zn_hyos_target_dev = scan.dev;
  zn_hyos_target_inode = scan.inode;
  memcpy(zn_hyos_spawner_image, scan.path, sizeof(zn_hyos_spawner_image));
  zn_hyos_available = true;
  zn_hyos_registration_open = true;

  LOGI("HyperOS runtime: spawner image at %p (dev %lu, inode %lu)",
       (void *)scan.start, (unsigned long)scan.dev, (unsigned long)scan.inode);

  return true;
}

void zn_hyos_begin_module_registration(const char *module_id) {
  zn_hyos_registering_id = module_id;
}

void zn_hyos_end_module_registration(void) {
  zn_hyos_registering_id = NULL;
}

/* INFO: Whether a module may register, and the only gate there is: the window
         has to be open (initialize() has run and the hooks are not installed
         yet), the structure has to be the one the contract describes, and the
         callback has to be there. A module that fails any of these is refused
         rather than served a table it would misinterpret. */
static int zn_hyos_register_module(const void *module_ptr) {
  if (!zn_hyos_registration_open || module_ptr == NULL) return ZN_FAILED;

  const struct ZygiskNextHyosModule *module = (const struct ZygiskNextHyosModule *)module_ptr;

  if (!zn_hyos_module_api_matches(module->target_api_version) || module->onAppSpecialized == NULL) {
    LOGE("HyperOS runtime: refusing a module built for API %d", module->target_api_version);

    return ZN_FAILED;
  }

  /* INFO: The same callback registered twice is one callback that would be
             delivered twice: a module that registers from two places, or two
             modules sharing a function, would see every specialization twice.
             The contract asks for one delivery per registered module, so the
             second registration is refused rather than served. */
  for (size_t i = 0; i < zn_hyos_registration_count; i++) {
    if (zn_hyos_registrations[i].module.onAppSpecialized == module->onAppSpecialized) {
      LOGE("HyperOS runtime: refusing a duplicate registration");

      return ZN_FAILED;
    }
  }

  if (zn_hyos_registration_count == zn_hyos_registration_capacity) {
    size_t capacity = zn_hyos_registration_capacity == 0 ? 4 : zn_hyos_registration_capacity * 2;

    struct zn_hyos_registration *grown = (struct zn_hyos_registration *)realloc(
      zn_hyos_registrations, capacity * sizeof(struct zn_hyos_registration));

    if (grown == NULL) {
      LOGE("HyperOS runtime: failed growing the module list");

      return ZN_FAILED;
    }

    zn_hyos_registrations = grown;
    zn_hyos_registration_capacity = capacity;
  }

  /* INFO: The contract is that the runtime copies the structure, so the module
            may reuse its storage the moment registerModule returns. */
  zn_hyos_registrations[zn_hyos_registration_count].module = *module;
  zn_hyos_registrations[zn_hyos_registration_count].module_id = zn_hyos_registering_id;
  zn_hyos_registration_count++;

  LOGI("HyperOS runtime: module registered (%zu total)", zn_hyos_registration_count);

  return ZN_SUCCESS;
}

/* INFO: The table handed to a module that asks for the runtime. It is one
         object for the life of the process, because the contract says the
         pointer a module receives stays valid for exactly that long. */
static const struct ZygiskNextRuntime zn_hyos_runtime_table = {
  .type = ZN_RUNTIME_HYOS,
  .api_version = ZYGISK_NEXT_HYOS_API_VERSION,
  .registerModule = zn_hyos_register_module
};

const struct ZygiskNextRuntime *zn_hyos_runtime(void) {
  return zn_hyos_available ? &zn_hyos_runtime_table : NULL;
}

/* INFO: A specialization string that does not fit, or that is not there at all,
         fails the whole dispatch rather than being handed on truncated: the
         contract promises complete strings, and half a package name is a wrong
         package name that no module can tell from a real one. */
static bool zn_hyos_copy_value(char *destination, size_t capacity, const char *source) {
  if (source == NULL || capacity == 0) return false;

  size_t length = 0;
  while (length < capacity && source[length] != '\0') length++;
  if (length == capacity) return false;

  memcpy(destination, source, length + 1);

  return true;
}

/* INFO: The name of the process being specialized, from its own cmdline.

         A read that does not end in a NUL inside the buffer, or that describes
         an empty name, is not a name: the contract has no way to say "the
         process has none", so the callback is not made rather than made with a
         placeholder that a module would treat as real. */
static bool zn_hyos_read_process_name(void) {
  int fd;
  do {
    fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
  } while (fd == -1 && errno == EINTR);

  if (fd == -1) return false;

  size_t length = 0;
  bool complete = false;

  while (length + 1 < sizeof(zn_hyos_process_name)) {
    char value = '\0';
    ssize_t got;

    do {
      got = read(fd, &value, sizeof(value));
    } while (got == -1 && errno == EINTR);

    if (got != (ssize_t)sizeof(value)) break;

    if (value == '\0') {
      complete = length != 0;

      break;
    }

    zn_hyos_process_name[length++] = value;
  }

  close(fd);

  zn_hyos_process_name[length] = '\0';

  return complete;
}

/* INFO: Fires every registered module's onAppSpecialized, once, for the child
         this process is.

         Nothing is dispatched before the hooks are installed and the child has
         a control session: what the contract promises a module is a runtime
         that is really running and really reporting, and a callback fired
         without one is a half-answer that reads as a whole one. */
static void zn_hyos_dispatch_specialized(const char *se_info, const char *package_name) {
  if (!zn_hyos_hooks_ready || !zn_hyos_child_ready || zn_hyos_child_dispatched) return;

  zn_hyos_child_dispatched = true;

  if (!zn_hyos_copy_value(zn_hyos_package_name, sizeof(zn_hyos_package_name), package_name) ||
      !zn_hyos_copy_value(zn_hyos_se_info, sizeof(zn_hyos_se_info), se_info) ||
      !zn_hyos_read_process_name()) {
    return;
  }

  const struct ZnHyosAppSpecializeArgs args = {
    .process_name = zn_hyos_process_name,
    .package_name = zn_hyos_package_name,
    .se_info = zn_hyos_se_info
  };

  LOGI("HyperOS runtime: app specialized, process=%s package=%s se_info=%s",
       zn_hyos_process_name, zn_hyos_package_name, zn_hyos_se_info);

  for (size_t i = 0; i < zn_hyos_registration_count; i++) {
    zn_hyos_registrations[i].module.onAppSpecialized(&args);

    /* INFO: Reported per module, right after the module was told: this is the
              runtime's record of what happened, and a module whose callback
              returned is not the same as one that was never reached. */
    if (zn_hyos_report != NULL && zn_hyos_registrations[i].module_id != NULL) {
      (void)zn_hyos_report(zn_hyos_registrations[i].module_id);
    }
  }
}

/* INFO: The state a forked application starts from.

         The session was opened by the spawner - before the fork - because the
         application cannot open one of its own by the time it needs to report:
         it is sandboxed by then, and the daemon's socket is not its to connect
         to. A child whose session could not be opened is told nothing rather
         than told something the daemon will never hear about.

         The three strings and the dispatch flag are cleared here because they
         are inherited from the parent: whatever the parent had captured, and
         whatever it had already dispatched, belongs to the parent's own
         process, and this child gets exactly one callback of its own. */
static void zn_hyos_reset_child_state(bool session_ready) {
  zn_hyos_child_ready = session_ready;
  zn_hyos_child_dispatched = false;
  zn_hyos_process_name[0] = '\0';
  zn_hyos_package_name[0] = '\0';
  zn_hyos_se_info[0] = '\0';
}

static pid_t zn_hyos_replacement_fork(void) {
  if (zn_hyos_original_fork == NULL) return -1;

  while (atomic_flag_test_and_set_explicit(&zn_hyos_fork_lock, memory_order_acquire)) {
  }

  const int session = zn_hyos_open_session != NULL ? zn_hyos_open_session() : -1;
  const pid_t result = zn_hyos_original_fork();

  if (result == 0) {
    /* INFO: Released before anything else runs in the child: the lock has to be
              free for the child's own children, and the session it inherited
              from the process it was forked from is not the one it reports
              over. The order matters - the lock is cleared first, because
              closing a descriptor is the one step here that can fail, and
              leaving a lock claimed by a thread that no longer exists would
              stop this process from ever forking again. */
    atomic_flag_clear_explicit(&zn_hyos_fork_lock, memory_order_release);

    if (zn_hyos_child_session_fd >= 0) close(zn_hyos_child_session_fd);

    zn_hyos_child_session_fd = session;
    zn_hyos_is_child = true;
    zn_hyos_reset_child_state(session >= 0);
  } else if (session >= 0) {
    /* INFO: The parent keeps no session: it belongs to the child that was just
              made, and holding the other end open would keep the daemon's
              session alive for as long as the spawner lives. */
    close(session);
  }

  if (result != 0) atomic_flag_clear_explicit(&zn_hyos_fork_lock, memory_order_release);

  return result;
}

static int zn_hyos_replacement_setcontext(uid_t uid, int is_system_server, const char *se_info, const char *package_name) {
  if (zn_hyos_original_setcontext == NULL) return -1;

  const int result = zn_hyos_original_setcontext(uid, is_system_server, se_info, package_name);

  if (result == 0) {
    zn_hyos_dispatch_specialized(se_info, package_name);
  } else if (zn_hyos_child_ready && !zn_hyos_child_dispatched) {
    /* INFO: Only worth saying for a process that was going to be told
              something: the spawner itself calls this too, and a refusal there
              concerns no module. */
    LOGW("HyperOS runtime: selinux_android_setcontext failed (%d), no module was told", result);
  }

  return result;
}

int zn_hyos_child_session(void) {
  return zn_hyos_child_session_fd;
}

bool zn_hyos_in_child(void) {
  return zn_hyos_is_child;
}

const char *zn_hyos_image_path(void) {
  return zn_hyos_spawner_image;
}

/* INFO: Puts the hooks back the way they were found. Both are registered again
         with their own original address as the handler, which is how LSPlt
         undoes a hook, and the commit is what applies it.

         The result is tracked per hook: a re-registration that could not be
         staged leaves that hook installed, and only the ones the commit
         applied are gone. Answering true with nothing restored - or clearing
         both originals when only one was restored - would leave a replacement
         live with a NULL original, and it answers -1 for every call: fork()
         and selinux_android_setcontext() would then fail for every
         application this spawner makes, until reboot. */
static bool zn_hyos_rollback_hooks(void) {
  if (zn_hyos_original_fork == NULL && zn_hyos_original_setcontext == NULL) return true;

  bool fork_staged = false;
  bool setcontext_staged = false;

  if (zn_hyos_original_fork != NULL) {
    fork_staged = zn_lsplt_register_hook(zn_hyos_target_dev, zn_hyos_target_inode, "fork",
                                         (void *)(uintptr_t)zn_hyos_original_fork, NULL) == 0;
  }

  if (zn_hyos_original_setcontext != NULL) {
    setcontext_staged = zn_lsplt_register_hook(zn_hyos_target_dev, zn_hyos_target_inode, "selinux_android_setcontext",
                                               (void *)(uintptr_t)zn_hyos_original_setcontext, NULL) == 0;
  }

  /* INFO: A rollback was needed and could not even be staged: the originals
            are kept and answered false, so the caller knows the replacements
            are still live and chaining through them stays the only path. */
  if (!fork_staged && !setcontext_staged) return false;

  if (zn_lsplt_commit_hook() != 0) return false;

  /* INFO: Only now is a hook really gone, and only the one that was staged:
          the replacements whose rollback did not take keep chaining to their
          originals, which stay in place for exactly that. */
  if (fork_staged) zn_hyos_original_fork = NULL;
  if (setcontext_staged) zn_hyos_original_setcontext = NULL;

  return zn_hyos_original_fork == NULL && zn_hyos_original_setcontext == NULL;
}

bool zn_hyos_install_hooks(void) {
  zn_hyos_registration_open = false;

  if (!zn_hyos_available || zn_hyos_registration_count == 0) return true;

  zn_hyos_original_fork = NULL;
  zn_hyos_original_setcontext = NULL;

  void *fork_backup = NULL;
  void *setcontext_backup = NULL;

  const bool registered =
    zn_lsplt_register_hook(zn_hyos_target_dev, zn_hyos_target_inode, "fork",
                           (void *)(uintptr_t)zn_hyos_replacement_fork, &fork_backup) == 0 &&
    zn_lsplt_register_hook(zn_hyos_target_dev, zn_hyos_target_inode, "selinux_android_setcontext",
                           (void *)(uintptr_t)zn_hyos_replacement_setcontext, &setcontext_backup) == 0;
  const bool committed = registered && zn_lsplt_commit_hook() == 0;

  /* INFO: A symbol the image does not import has no entry to rewrite and comes
            back as NULL, which is not a hook: LSPlt answers 0 for a
            registration it accepted either way, so what was really placed is
            read off the pointers it handed back. */
  zn_hyos_original_fork = (zn_hyos_fork_fn)(uintptr_t)fork_backup;
  zn_hyos_original_setcontext = (zn_hyos_setcontext_fn)(uintptr_t)setcontext_backup;

  /* INFO: A hook that was not really placed leaves its original NULL, and the
            runtime is only as good as the two together: without fork there is no
            child to report from, without setcontext nothing ever fires. So both
            are required, and a session is opened here as the last proof that the
            reporting side is reachable at all - the spawner is the one process
            that can open one, and if it cannot, no application ever will. */
  bool session_ready = false;

  if (committed && zn_hyos_original_fork != NULL && zn_hyos_original_setcontext != NULL && zn_hyos_open_session != NULL) {
    const int session = zn_hyos_open_session();

    session_ready = session >= 0;

    if (session >= 0) close(session);
  }

  if (!session_ready) {
    const bool rolled_back = zn_hyos_rollback_hooks();

    if (rolled_back) {
      zn_hyos_original_fork = NULL;
      zn_hyos_original_setcontext = NULL;
    }

    LOGE("HyperOS runtime: hooks are not installed, rolled back=%u", rolled_back ? 1u : 0u);

    return false;
  }

  zn_hyos_hooks_ready = true;

  LOGI("HyperOS runtime: hooks installed for %zu module(s)", zn_hyos_registration_count);

  return true;
}
