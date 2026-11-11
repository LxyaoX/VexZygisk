#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <dlfcn.h>
#include <errno.h>
#include <regex.h>
#include <semaphore.h>

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sched.h>
#include <unistd.h>

#include <csoloader.h>
#include <plti.h>

#include "daemon.h"
#include "misc.h"
#include "module.h"

#include "art_method.h"
#include "cpp_strings.h"
#include "registers.h"
#include "hiding.h"
#include "unmount.h"
#include "zn_loader.h"

void *start_addr = NULL;
size_t block_size = 0;
void *injector_handle = NULL;

/* INFO: dlclose, reached through the exact type of the hook that calls it.

         The teardown has to leave this library with a jump and not a call: a
         call's return would land on an instruction in a library that is gone by
         the time it runs, which is the whole reason the reference
         implementation wraps its own unmap in musttail. clang allows that only
         between functions whose signatures agree - the same number of
         parameters and the same types, which is what the two errors that
         produced this line said in turn - and the hook around it takes the
         (void *, size_t) of the function it replaces. dlclose takes one
         parameter, so nothing about it matches on its own: the reference never
         met this because munmap happens to take two, of a matching kind.

         So the call goes through this, and on AArch64 the argument dlclose does
         not declare is a register it never reads. What the cast buys is the
         jump; the pragma is only there because the conversion is the point of
         the line and a build does not need to be told so on every file. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-function-type-mismatch"
static int (*const injector_close)(void *handle, size_t unused) = (int (*)(void *, size_t))dlclose;
#pragma clang diagnostic pop

/* INFO: Flag indices */
enum {
  POST_SPECIALIZE,
  APP_FORK_AND_SPECIALIZE,
  APP_SPECIALIZE,
  SERVER_FORK_AND_SPECIALIZE,
  DO_REVERT_UNMOUNT,
  SKIP_FD_SANITIZATION,
  SPECIALIZE_IN_PLACE,

  FLAG_MAX
};

#define MAX_FD_SIZE 1024
#define MAX_REGISTER_INFO 64
#define MAX_IGNORE_INFO 64
#define MAX_EXEMPTED_FDS 128

struct register_info {
  regex_t regex;
  char *symbol;
  void *callback;
  void **backup;
};

struct ignore_info {
  regex_t regex;
  char *symbol;
};

struct zygisk_context {
  JNIEnv *env;
  union {
    void *ptr;
    struct app_specialize_args_v5 *app;
    struct server_specialize_args_v1 *server;
  } args;

  const char *process;

  int pid;
  uint32_t flags;
  uint32_t info_flags;
  uint8_t allowed_fds[MAX_FD_SIZE];
  int exempted_fds[MAX_EXEMPTED_FDS];
  size_t exempted_fds_count;

  pthread_mutex_t hook_info_lock;
  struct register_info register_info[MAX_REGISTER_INFO];
  size_t register_info_count;
  struct ignore_info ignore_info[MAX_IGNORE_INFO];
  size_t ignore_info_count;
};

/* INFO: Current context */
static struct zygisk_context *g_ctx = NULL;

/* INFO: Helper macros for flags */
#define FLAG_SET(ctx, f) ((ctx)->flags |= (1u << (f)))
#define FLAG_GET(ctx, f) (((ctx)->flags & (1u << (f))) != 0)

#define DCL_PRE_POST(name)                                   \
  static void rz_## name ##_pre(struct zygisk_context *ctx); \
  static void rz_## name ##_post(struct zygisk_context *ctx)

/* INFO: Early declarations */
static void rz_init(struct zygisk_context *ctx, JNIEnv *env, void *args);
static void rz_cleanup(struct zygisk_context *ctx);

DCL_PRE_POST(run_modules);
DCL_PRE_POST(fork);
DCL_PRE_POST(app_specialize);
DCL_PRE_POST(nativeForkAndSpecialize);
DCL_PRE_POST(nativeSpecializeAppProcess);
DCL_PRE_POST(nativeForkSystemServer);

#undef DCL_PRE_POST

/* INFO: True in the processes that have to run the specialise pipeline: the
           child of a successful fork, and the in-place path
           (nativeSpecializeAppProcess never forks, it specialises the caller).

           The parked value rz_init() writes is -1, and a failed fork leaves the
           very same -1, so the pid alone cannot tell "no fork happened" from
           "the fork failed". Reading the second as a child sends the parent -
           which is the zygote itself - through specialisation and then through
           rz_cleanup's self-unmap. The flag is what separates them. */
static inline bool is_zygote_child(struct zygisk_context *ctx) {
  return ctx->pid == 0 || FLAG_GET(ctx, SPECIALIZE_IN_PLACE);
}

struct plt_hook_entry {
  const char *lib_path;
  const char *symbol;
  void *new_func;
  void **backup;
};

struct jni_hook_entry {
  char *class_name;
  JNINativeMethod *methods;
  size_t methods_count;
};

struct plti plti_ctx;

static struct plt_hook_entry *plt_hook_list = NULL;
static size_t plt_hook_list_count = 0;

static struct jni_hook_entry *jni_hook_list = NULL;
static size_t jni_hook_list_count = 0;

struct rezygisk_module *zygisk_modules = NULL;
size_t zygisk_module_length = 0;

/* INFO: The daemon reports whether any Zygisk Next module exists at all in
           the GetProcessFlags answer; until the first answer arrives the
           state is unknown and the per-fork query still runs. */
static bool zn_presence_known = false;
static bool zn_modules_present = false;

/* INFO: The specialize pipeline is a process-global sequence (g_ctx, the cached
           fork pid). The classic zygote is single-threaded, which is what makes
           that safe; HyperOS's hyos_spawner spawns in parallel, so two threads
           could interleave and hand both parents the same cached child. A
           semaphore serializes it, chosen over a mutex because the fork
           duplicates it into the child and a semaphore has no owning thread to
           strand the child's copy. */
static sem_t spawn_pipeline_sem;
static pthread_once_t spawn_pipeline_once = PTHREAD_ONCE_INIT;

static void spawn_pipeline_sem_init(void) {
  sem_init(&spawn_pipeline_sem, 0, 1);
}

static void spawn_pipeline_enter(void) {
  pthread_once(&spawn_pipeline_once, spawn_pipeline_sem_init);

  while (sem_wait(&spawn_pipeline_sem) == -1 && errno == EINTR) {
  }
}

static void spawn_pipeline_leave(void) {
  sem_post(&spawn_pipeline_sem);
}

static bool hooks_removed = false;
static bool enable_unloader = false;

/* INFO: Helper function to add to PLT hook list */
static bool plt_hook_list_add(const char *lib_path, const char *symbol, void *new_func, void **backup) {
  struct plt_hook_entry *new_plt_hook_list = realloc(plt_hook_list, (plt_hook_list_count + 1) * sizeof(struct plt_hook_entry));
  if (!new_plt_hook_list) {
    LOGE("Failed to reallocate buffer for PLT hook list");

    return false;
  }
  plt_hook_list = new_plt_hook_list;

  plt_hook_list[plt_hook_list_count].lib_path = lib_path;
  plt_hook_list[plt_hook_list_count].symbol = symbol;
  plt_hook_list[plt_hook_list_count].new_func = new_func;
  plt_hook_list[plt_hook_list_count].backup = backup;
  plt_hook_list_count++;

  return true;
}

/* INFO: Helper function to add to JNI hook list */
static void jni_hook_list_add(const char *class_name, JNINativeMethod *methods, size_t count) {
  struct jni_hook_entry *new_jni_hook_list = realloc(jni_hook_list, (jni_hook_list_count + 1) * sizeof(struct jni_hook_entry));
  if (!new_jni_hook_list) {
    LOGE("Failed to reallocate buffer for JNI hook list");

    return;
  }
  jni_hook_list = new_jni_hook_list;

  jni_hook_list[jni_hook_list_count].class_name = strdup(class_name);
  if (!jni_hook_list[jni_hook_list_count].class_name) {
    LOGE("Failed to duplicate class name for hook list");

    return;
  }

  jni_hook_list[jni_hook_list_count].methods = malloc(count * sizeof(JNINativeMethod));
  if (!jni_hook_list[jni_hook_list_count].methods) {
    LOGE("Failed to allocate memory for methods in hook list");

    free(jni_hook_list[jni_hook_list_count].class_name);

    return;
  }

  memcpy(jni_hook_list[jni_hook_list_count].methods, methods, count * sizeof(JNINativeMethod));

  jni_hook_list[jni_hook_list_count].methods_count = count;
  jni_hook_list_count++;
}

static bool update_mnt_ns(enum mount_namespace_state mns_state, bool dry_run) {
  char ns_path[PATH_MAX];
  if (!rezygiskd_update_mns(mns_state, ns_path, sizeof(ns_path))) {
    PLOGE("Failed to update mount namespace");

    return false;
  }

  if (dry_run) return true;

  int updated_ns = open(ns_path, O_RDONLY | O_CLOEXEC);
  if (updated_ns == -1) {
    PLOGE("Failed to open mount namespace [%s]", ns_path);

    return false;
  }

  LOGD("set mount namespace to [%s] fd=[%d]", ns_path, updated_ns);

  if (setns(updated_ns, CLONE_NEWNS) == -1) {
    PLOGE("Failed to set mount namespace [%s]", ns_path);

    close(updated_ns);

    return false;
  }

  close(updated_ns);

  return true;
}

/* INFO: Hook function declarations */
#define DCL_HOOK_FUNC(ret, func, ...) \
  ret (*old_##func)(__VA_ARGS__);     \
  ret new_##func(__VA_ARGS__)

/* INFO: VexZygisk already performs a fork in rz_fork_pre, because of that,
           we avoid duplicate fork in nativeForkAndSpecialize and nativeForkSystemServer
           by caching the pid in fork_pre function and only returning the cached
           pid while it is non-negative, i.e. also for the forked child itself.
           A negative pid means the cached fork failed and the caller has to fork. */
DCL_HOOK_FUNC(int, fork) {
  if (g_ctx && g_ctx->pid >= 0) return g_ctx->pid;

  int pid = old_fork();

  /* INFO: rz_fork_pre's own fork failed, so this one decides the process.
             Recording its result keeps is_zygote_child() truthful: the child
             born here would otherwise be left on the parked -1 and never
             specialise, and a second failure would leave a value that reads as
             "no fork happened" and hands the zygote to the child path. */
  if (g_ctx) g_ctx->pid = pid;

  return pid;
}

/* INFO: file_path is a std::string in the actual class. We represent it as opaque bytes. */
#define STD_STRING_SIZE 24

struct FileDescriptorInfo {
  const int fd;
  const struct stat stat;
  /* INFO: std::string, actually */
  char file_path_storage[STD_STRING_SIZE];
  const int open_flags;
  const int fd_flags;
  const int fs_flags;
  const off_t offset;
  const bool is_sock;
};

/* INFO: This hook avoids that umounted overlays made by root modules lead to Zygote
           to Abort its operation as it cannot open anymore.

   SOURCES:
     - https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-14.0.0_r1/core/jni/fd_utils.cpp#346
     - https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-14.0.0_r1/core/jni/fd_utils.cpp#544
     - https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-14.0.0_r1/core/jni/com_android_internal_os_Zygote.cpp#2329
*/
DCL_HOOK_FUNC(void, _ZNK18FileDescriptorInfo14ReopenOrDetach, void *_this, void *fail_fn) {
  const int fd = *(const int *)((uintptr_t)_this + offsetof(struct FileDescriptorInfo, fd));
  const void *file_path_std_string = (const void *)((uintptr_t)_this + offsetof(struct FileDescriptorInfo, file_path_storage));
  const char *file_path = read_std_string(file_path_std_string);
  const bool is_sock = *(const bool *)((uintptr_t)_this + offsetof(struct FileDescriptorInfo, is_sock));

  /* INFO: read_std_string() may return NULL for a moved-from or otherwise
           malformed std::string; dereferencing it below would crash the fd
           sanitization hook on every fork. Treat a missing path as "cannot
           verify, leave the fd alone" and defer to the original. */
  if (file_path == NULL)
    goto bypass_fd_check;

  if (is_sock)
    goto bypass_fd_check;

  if (strncmp(file_path, "/memfd:/boot-image-methods.art", strlen("/memfd:/boot-image-methods.art")) == 0)
    goto bypass_fd_check;

  if (access(file_path, F_OK) == -1) {
    LOGD("Failed to open file %s, detaching it", file_path);

    close(fd);

    return;
  }

  bypass_fd_check:
    old__ZNK18FileDescriptorInfo14ReopenOrDetach(_this, fail_fn);
}

static void unhook_functions(void);
/* INFO: The teardown runs here, on the first pthread_attr_setstacksize of the
           main thread, because that is the last moment before the application
           executes code of its own: the hooks come off and the mappings this
           process was never meant to name stop naming anything, before there is
           an application around to look.

         The library is closed here rather than unmapped, and the difference is
           the whole of what the process keeps. Unmapping the block by hand is
           what an earlier design did, and it left the linker holding a module
           entry for memory that was gone: a detector walking that list read a
           header that had been unmapped under it and took the application down,
           which is why the block was then kept as an anonymous copy of itself
           instead. Closing the handle takes the entry and the mapping out
           together, so neither problem exists to be worked around - and an
           application that has loaded nothing of ours has nothing of ours to
           find. */
DCL_HOOK_FUNC(int, pthread_attr_setstacksize, void *target, size_t size) {
  int res = old_pthread_attr_setstacksize((pthread_attr_t *)target, size);
  LOGV("Call pthread_attr_setstacksize in [tid, pid]: %d, %d", gettid(), getpid());

  if (!enable_unloader) return res;

  /* INFO: Only perform unloading on the main thread */
  if (gettid() != getpid()) return res;

  if (hooks_removed) {
    unhook_functions();

    csoloader_deinit();

    if (!hooks_removed) {
      LOGW("A hook could not be removed, so the library stays as it is");

      enable_unloader = false;

      free(zygisk_modules);
      zygisk_modules = NULL;

      plti_deinit(&plti_ctx);

      return res;
    }

    /* INFO: Modules might use libzygisk.so after postAppSpecialize. We can only
               free it when we are really before hiding it. */
    free(zygisk_modules);
    zygisk_modules = NULL;

    plti_deinit(&plti_ctx);

    /* INFO: Hiding rather than unmapping, and it is the last of the teardown
               on purpose: the block this code runs from is replaced with a copy
               of itself, so the mapping that comes back is anonymous while the
               bytes and the permissions are the ones already executing.

               Skipped when the specialize path already did it here. That path
               runs after the modules have had their callbacks, so every library
               they mapped is covered by it; a second pass could only read the
               whole map table - through a fork, so the read leaves no mark - to
               find nothing, which is the most expensive thing either pass does.
               A process that path never reached still gets this one. */
    if (module_maps_hidden()) {
      LOGD("Module mappings were already hidden at specialize time");
    } else if (!hide_module_maps()) {
      LOGW("Failed to hide the module mappings");
    }

    /* INFO: And then the library itself goes, which is the one thing that pass
               cannot do for it: a name that has been replaced is still a
               mapping, and a mapping is what a scan reads.

               Closing the handle is the consequence of how the injection is
               done. The target's own linker loaded this library (ptracer.c), so
               the loader is in that linker's module list, and unmapping the
               block under it is what used to take an application down. dlclose
               removes the entry and the mapping in one step.

               It runs after the pass above on purpose, so a linker that
               declines to unload - bionic returns without unloading when the
               library has handed out a TLS block - leaves the process in the
               state every earlier release shipped: hidden, not gone. That is
               the floor, and it is why trying costs nothing.

               musttail, for the reason the reference implementation needs it
               for its own unmap: the return would otherwise be an instruction
               in a library that no longer exists by the time dlclose comes
               back. Jumping out of the frame means libart - the caller of
               pthread_attr_setstacksize - resumes instead.

               It goes through injector_close rather than calling dlclose
               directly, because a musttail cannot change arity; the note on
               that pointer says the rest. */
    if (injector_handle == NULL) {
      LOGD("kept libzygisk.so mapped at %p with size %zu (no handle to close)", start_addr, block_size);

      return res;
    }

    LOGD("closing libzygisk.so at %p with size %zu", start_addr, block_size);

    [[clang::musttail]] return injector_close(injector_handle, 0);
  }

  return res;
}

static void initialize_jni_hook(void);
static bool can_hook_jni = false;

DCL_HOOK_FUNC(char *, strdup, const char *str) {
  /* INFO: The comparison runs on every strdup the process makes, and there is
            only ever the one string it looks for. Once the hook is installed
            the answer cannot change, so the search is skipped - and the retry
            this exists for still happens, because the flag is set only by a
            setup that got all the way through. */
  if (!can_hook_jni && strcmp(str, "com.android.internal.os.ZygoteInit") == 0) {
    LOGV("strdup %s", str);

    initialize_jni_hook();
  }

  return old_strdup(str);
}

static void hook_unloader(void);
/*
  INFO: Our goal is to get called after libart.so is loaded, but before ART actually starts running.
          If we are too early, we won't find libart.so in maps, and if we are too late, we could make other
          threads crash if they try to use the PLT while we are in the process of hooking it.
          For this task, hooking property_get was chosen as there are lots of calls to this, so it's
          relatively unlikely to break.

        After we succeed in getting called at a point where libart.so is already loaded, we will ignore
          the rest of the property_get calls.
  SOURCES:
   - https://github.com/aosp-mirror/platform_frameworks_base/blob/1cdfff555f4a21f71ccc978290e2e212e2f8b168/core/jni/AndroidRuntime.cpp#L1266
   - https://github.com/aosp-mirror/platform_frameworks_base/blob/1cdfff555f4a21f71ccc978290e2e212e2f8b168/core/jni/AndroidRuntime.cpp#L791
*/
DCL_HOOK_FUNC(int, property_get, const char *key, char *value, const char *default_value) {
  hook_unloader();

  return old_property_get(key, value, default_value);
}

#undef DCL_HOOK_FUNC

static jint MODIFIER_NATIVE = 0;
static jmethodID member_getModifiers = NULL;

void hook_jni_methods(JNIEnv *env, const char *clz, JNINativeMethod *methods, int numMethods) {
  if (!can_hook_jni) return;

  jclass clazz = (*env)->FindClass(env, clz);
  if (!clazz) {
    (*env)->ExceptionClear(env);

    memset(methods, 0, numMethods * sizeof(JNINativeMethod));

    return;
  }

  JNINativeMethod hooks[32];
  size_t hooks_count = 0;
  bool overflow_logged = false;

  for (int i = 0; i < numMethods; i++) {
    bool is_static = false;

    JNINativeMethod *nm = &methods[i];
    jmethodID mid = (*env)->GetMethodID(env, clazz, nm->name, nm->signature);
    if (!mid) {
      (*env)->ExceptionClear(env);
      mid = (*env)->GetStaticMethodID(env, clazz, nm->name, nm->signature);
      is_static = true;
    }

    if (!mid) {
      (*env)->ExceptionClear(env);
      nm->fnPtr = NULL;

      continue;
    }

    jobject method = (*env)->ToReflectedMethod(env, clazz, mid, is_static);

    /* INFO: Checked before it is used as a receiver: an allocation failure in
              the reflected-method path answers NULL, and CallIntMethod on NULL
              is what turns that into a crash in the zygote. */
    if (method == NULL) {
      (*env)->ExceptionClear(env);
      nm->fnPtr = NULL;

      continue;
    }

    jint modifier = (*env)->CallIntMethod(env, method, member_getModifiers);
    if ((*env)->ExceptionCheck(env) || (modifier & MODIFIER_NATIVE) == 0) {
      (*env)->ExceptionClear(env);
      nm->fnPtr = NULL;

      (*env)->DeleteLocalRef(env, method);

      continue;
    }

    void *art_method = amethod_from_reflected_method(env, method);
    if (hooks_count < (sizeof(hooks) / sizeof(hooks[0]))) {
      hooks[hooks_count++] = *nm;
    } else if (!overflow_logged) {
      /* INFO: The registration table is fixed at 32 entries; a module that
                hooks more than that loses the rest silently, while the loop
                still rewrote its fnPtr as though every hook had gone in.
                Said once, at the boundary. */
      overflow_logged = true;

      LOGE("more than %zu native methods for %s: the ones past the limit are not hooked",
           sizeof(hooks) / sizeof(hooks[0]), clz);
    }

    void *orig = amethod_get_data((uintptr_t)art_method);
    nm->fnPtr = orig;

    LOGV("replaced %s %s orig %p: %s", clz, nm->name, orig, nm->signature);

    (*env)->DeleteLocalRef(env, method);
  }

  if (hooks_count == 0) {
    (*env)->DeleteLocalRef(env, clazz);

    return;
  }

  /* INFO: Checked, because a registration that did not take leaves the module's
            JNI hooks silently absent - the hook list is built here, applied
            here, and nothing later revisits it. */
  if ((*env)->RegisterNatives(env, clazz, hooks, (jint)hooks_count) != JNI_OK) {
    (*env)->ExceptionClear(env);

    LOGE("failed to register the JNI hooks for %s", clz);
  }

  (*env)->DeleteLocalRef(env, clazz);
}

/* INFO: JNI method hook definitions */
#include "jni_hooks.h"

static void initialize_jni_hook(void) {
  jint (*get_created_java_vms)(JavaVM **, jsize, jsize *) = (jint (*)(JavaVM **, jsize, jsize *))dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");
  if (!get_created_java_vms) {
    struct maps_info *maps = parse_maps_safe("self");
    if (!maps) {
      LOGE("Failed to scan maps for plt_hook_register_v4");

      return;
    }

    for (size_t i = 0; i < maps->length; i++) {
      struct map_entry *map = &maps->maps[i];
      if (map->path == NULL || !strstr(map->path, "/libnativehelper.so")) continue;

      /* INFO: RTLD_NOLOAD answers the TODO that lived here: the library is
                already mapped (it is in our own maps), so this hands back the
                existing handle without bumping the reference count — and
                without the dlopen/dlclose pair that briefly moved it. */
      void *handle = dlopen(map->path, RTLD_LAZY | RTLD_NOLOAD);
      if (!handle) {
        LOGE("Failed to dlopen %s: %s", map->path, dlerror());

        break;
      }

      get_created_java_vms = (jint (*)(JavaVM **, jsize, jsize *))dlsym(handle, "JNI_GetCreatedJavaVMs");

      break;
    }

    free_maps(maps);

    if (!get_created_java_vms) {
      LOGE("Failed to find JNI_GetCreatedJavaVMs");

      return;
    }
  }

  JavaVM *vm = NULL;
  jsize num = 0;
  jint res = get_created_java_vms(&vm, 1, &num);
  if (res != JNI_OK || !vm) return;

  JNIEnv *env = NULL;
  res = (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);
  if (res != JNI_OK || !env) return;

  /* INFO: Every lookup below clears its own failure: this returns into the
            strdup hook and from there into ART runtime code, and a pending
            exception would abort the zygote on the next JNI call it makes. */
  jclass classMember = (*env)->FindClass(env, "java/lang/reflect/Member");
  if (classMember) {
    member_getModifiers = (*env)->GetMethodID(env, classMember, "getModifiers", "()I");
    if (!member_getModifiers) (*env)->ExceptionClear(env);
  } else {
    (*env)->ExceptionClear(env);
  }

  jclass classModifier = (*env)->FindClass(env, "java/lang/reflect/Modifier");
  if (classModifier) {
    jfieldID fieldId = (*env)->GetStaticFieldID(env, classModifier, "NATIVE", "I");
    if (fieldId) MODIFIER_NATIVE = (*env)->GetStaticIntField(env, classModifier, fieldId);
    else (*env)->ExceptionClear(env);
  } else {
    (*env)->ExceptionClear(env);
  }

  (*env)->DeleteLocalRef(env, classMember);
  (*env)->DeleteLocalRef(env, classModifier);

  if (!member_getModifiers || MODIFIER_NATIVE == 0) return;

  if (!amethod_init(env)) {
    LOGE("failed to init amethod");

    return;
  }

  can_hook_jni = true;
  do_hook_zygote(env);

  /* INFO: ART leaks through libc strings from VexZygisk. We immediately
             clear them here. */
  registers_clear();
}

/* INFO: Module registration and API functions */
static void api_plt_hook_register(const char *regex, const char *symbol, void *fn, void **backup) {
  if (!g_ctx || !regex || !symbol || !fn || g_ctx->register_info_count >= MAX_REGISTER_INFO) return;

  regex_t re;
  if (regcomp(&re, regex, REG_NOSUB) != 0) return;

  /* INFO: Copied before the lock, and its failure handled here rather than
            left to the hooking pass: a NULL symbol would reach the strcmp that
            matches registrations against modules and dereference it. A failed
            copy also has to give the compiled regex back, which the early
            return used to skip. */
  char *symbol_copy = strdup(symbol);
  if (symbol_copy == NULL) {
    PLOGE("copy the symbol name");

    regfree(&re);

    return;
  }

  pthread_mutex_lock(&g_ctx->hook_info_lock);

  g_ctx->register_info[g_ctx->register_info_count].regex = re;
  g_ctx->register_info[g_ctx->register_info_count].symbol = symbol_copy;
  g_ctx->register_info[g_ctx->register_info_count].callback = fn;
  g_ctx->register_info[g_ctx->register_info_count].backup = backup;
  g_ctx->register_info_count++;

  pthread_mutex_unlock(&g_ctx->hook_info_lock);
}

static void api_plt_hook_exclude(const char *regex, const char *symbol) {
  if (!g_ctx || !regex || g_ctx->ignore_info_count >= MAX_IGNORE_INFO) return;

  regex_t re;
  if (regcomp(&re, regex, REG_NOSUB) != 0) return;

  pthread_mutex_lock(&g_ctx->hook_info_lock);

  g_ctx->ignore_info[g_ctx->ignore_info_count].regex = re;
  g_ctx->ignore_info[g_ctx->ignore_info_count].symbol = symbol ? strdup(symbol) : NULL;
  g_ctx->ignore_info_count++;

  pthread_mutex_unlock(&g_ctx->hook_info_lock);
}

/* INFO: Drops every pending PLT registration; both lists live in the context
           and carry compiled regexes plus duplicated strings. */
static void clear_hook_info(struct zygisk_context *ctx) {
  for (size_t i = 0; i < ctx->register_info_count; i++) {
    regfree(&ctx->register_info[i].regex);
    free(ctx->register_info[i].symbol);
  }
  ctx->register_info_count = 0;

  for (size_t i = 0; i < ctx->ignore_info_count; i++) {
    regfree(&ctx->ignore_info[i].regex);
    free(ctx->ignore_info[i].symbol);
  }
  ctx->ignore_info_count = 0;
}

/* INFO: Releases the v4 deferred PLT hook list; the paths and symbols were
           duplicated at registration time, the rest are borrowed pointers. */
static void free_plt_hook_list(void) {
  if (plt_hook_list == NULL) return;

  for (size_t i = 0; i < plt_hook_list_count; i++) {
    free((void *)plt_hook_list[i].lib_path);
    free((void *)plt_hook_list[i].symbol);
  }

  free(plt_hook_list);
  plt_hook_list = NULL;
  plt_hook_list_count = 0;
}

/* INFO: The mapping table the hook registrations of one batch share.

         A module registers its hooks one after another and then commits, and
         each registration used to read the maps afresh - a fork every time,
         because the read has to stay invisible. Nothing changes between two
         registrations of the same batch: the library being hooked is already
         mapped, which is the only reason a register call can name it at all.

         The commits are deliberately not served from here. api_plt_hook_commit
         walks a table of its own, because a library mapped between the last
         register and the commit has to be visible there; both of them drop
         this one instead, so the next batch starts from the process as it is
         then. */
static struct maps_info *plt_hook_maps_cache = NULL;

static struct maps_info *plt_hook_take_maps(bool refresh) {
  if (refresh || plt_hook_maps_cache == NULL) {
    struct maps_info *fresh = parse_maps_safe("self");
    if (fresh == NULL) return NULL;

    if (plt_hook_maps_cache != NULL) free_maps(plt_hook_maps_cache);
    plt_hook_maps_cache = fresh;
  }

  return plt_hook_maps_cache;
}

static void plt_hook_forget_maps(void) {
  if (plt_hook_maps_cache == NULL) return;

  free_maps(plt_hook_maps_cache);
  plt_hook_maps_cache = NULL;
}

static bool api_plt_hook_commit(void) {
  if (!g_ctx || g_ctx->register_info_count == 0) return false;

  pthread_mutex_lock(&g_ctx->hook_info_lock);

  struct maps_info *map_infos = parse_maps_safe("self");
  if (!map_infos) {
    LOGE("Failed to scan maps for self");

    pthread_mutex_unlock(&g_ctx->hook_info_lock);

    return false;
  }

  bool any_failed = false;
  for (size_t i = 0; i < map_infos->length; i++) {
    struct map_entry *map = &map_infos->maps[i];
    if (map->offset != 0 || !map->is_private || !(map->perms & PROT_READ)) continue;

    for (size_t r = 0; r < g_ctx->register_info_count; r++) {
      struct register_info *reg = &g_ctx->register_info[r];
      if (regexec(&reg->regex, map->path, 0, NULL, 0) != 0) continue;

      bool ignored = false;
      for (size_t ig = 0; ig < g_ctx->ignore_info_count; ig++) {
        struct ignore_info *ign = &g_ctx->ignore_info[ig];
        if (regexec(&ign->regex, map->path, 0, NULL, 0) != 0) continue;
        if (ign->symbol && strcmp(ign->symbol, reg->symbol) != 0) continue;

        ignored = true;

        break;
      }

      if (!ignored && !plti_add_hook(&plti_ctx, map->path, reg->symbol, reg->callback, reg->backup)) {
        LOGE("Failed to register PLT hook for %s in %s", reg->symbol, map->path);

        any_failed = true;
      }
    }
  }

  free_maps(map_infos);

  clear_hook_info(g_ctx);

  pthread_mutex_unlock(&g_ctx->hook_info_lock);

  /* INFO: The batch is over: what the registrations shared no longer describes the
            process, because what they registered has just been mapped into it. */
  plt_hook_forget_maps();

  return !any_failed;
}

static void api_plt_hook_register_v4(dev_t dev, ino_t inode, const char *symbol, void *fn, void **backup) {
  if (!g_ctx || !symbol || !fn) return;

  uintptr_t lib_start = 0;
  const char *lib_path = NULL;

  /* INFO: Twice at most. A library mapped after the table was taken is not in
            it, and the answer in the meantime has to be the honest one: drop
            the table and ask again with a current one. */
  for (int attempt = 0; attempt < 2 && lib_path == NULL; attempt++) {
    struct maps_info *maps = plt_hook_take_maps(attempt == 1);
    if (maps == NULL) {
      LOGE("Failed to scan maps for plt_hook_register_v4");

      return;
    }

    for (size_t k = 0; k < maps->length; k++) {
      struct map_entry *entry = &maps->maps[k];
      if (entry->dev != dev || entry->inode != inode) continue;

      lib_start = entry->start;
      lib_path = entry->path;

      break;
    }

    if (lib_path == NULL) plt_hook_forget_maps();
  }

  if (!lib_path) {
    LOGE("Failed to find library with dev %zu and inode %zu for hook %s", (size_t)dev, (size_t)inode, symbol);

    return;
  }

  /* INFO: Copied while the table that named it is still held: the entry
            belongs to the cache, and the copy is what outlives it. */
  char *lib_path_copy = strdup(lib_path);
  if (!lib_path_copy) {
    LOGE("Failed to duplicate library path for hook %s: %s", symbol, lib_path);

    return;
  }

  if (!plti_add_manual_lib(&plti_ctx, lib_path_copy, lib_start)) {
    LOGE("Failed to add manual library for hook %s: %s", symbol, lib_path_copy);

    free(lib_path_copy);

    return;
  }

  char *symbol_copy = strdup(symbol);
  if (!symbol_copy) {
    LOGE("Failed to duplicate symbol name for hook %s in %s", symbol, lib_path_copy);

    free(lib_path_copy);

    return;
  }

  if (!plt_hook_list_add(lib_path_copy, symbol_copy, fn, backup)) {
    LOGE("Failed to add plt_hook entry for %s in %s", symbol, lib_path_copy);

    free(lib_path_copy);
    free(symbol_copy);

    return;
  }
}

static void api_exempt_fd(int fd) {
  if (!g_ctx) return;

  if (FLAG_GET(g_ctx, POST_SPECIALIZE) || FLAG_GET(g_ctx, SKIP_FD_SANITIZATION)) return;
  if (!FLAG_GET(g_ctx, APP_FORK_AND_SPECIALIZE)) return;

  /* INFO: Said rather than swallowed: a module that asks after the limit, or
            outside the one path the exemption can act on, loses the fd with
            no other signal than the fd closing later. */
  if (g_ctx->exempted_fds_count >= MAX_EXEMPTED_FDS) {
    LOGW("exempt_fd(%d) refused: the exemption table is full", fd);

    return;
  }

  g_ctx->exempted_fds[g_ctx->exempted_fds_count++] = fd;

  return;
}

static bool api_plt_hook_commit_v4(void) {
  if (!g_ctx) return false;

  bool any_failed = false;
  for (size_t i = 0; i < plt_hook_list_count; i++) {
    struct plt_hook_entry *entry = &plt_hook_list[i];
    if (!plti_add_hook(&plti_ctx, entry->lib_path, entry->symbol, entry->new_func, entry->backup)) {
      LOGE("Failed to register plt_hook \"%s\" in %s with PLTI", entry->symbol, entry->lib_path);

      any_failed = true;
    }
  }

  free_plt_hook_list();
  plt_hook_forget_maps();

  return !any_failed;
}

/* INFO: Avoid common mistakes of not utilizing implementation member (impl) when calling
           any Zygisk API functions by logging that error. */
#define RZID_MAGIC ('R' + 'Z' + 'I' + 'D')
#define ENCODE_ID(id) ((void *)((size_t)(id) + RZID_MAGIC))
#define DECODE_ID(ptr) ((size_t)(ptr) - RZID_MAGIC)

/* INFO: Decodes an encoded module id into its index, or SIZE_MAX when the
           caller passed something that was never handed out. */
static size_t decode_module_id(void *id) {
  if ((size_t)id < RZID_MAGIC || DECODE_ID(id) >= zygisk_module_length) {
    LOGE("Invalid (encoded) module id %zu", (size_t)id);

    return SIZE_MAX;
  }

  return DECODE_ID(id);
}

static int api_connect_companion(void *id) {
  if (!g_ctx) return -1;

  size_t index = decode_module_id(id);
  if (index == SIZE_MAX) return -1;

  return rezygiskd_connect_companion(index);
}

static void api_set_option(void *id, enum rezygisk_options opt) {
  if (!g_ctx) return;

  size_t index = decode_module_id(id);
  if (index == SIZE_MAX) return;

  switch (opt) {
    case FORCE_DENYLIST_UNMOUNT: {
      FLAG_SET(g_ctx, DO_REVERT_UNMOUNT);

      break;
    }
    case DLCLOSE_MODULE_LIBRARY: {
      struct rezygisk_module *m_lib = &zygisk_modules[index];
      m_lib->unload = true;

      break;
    }
  }
}

static int api_get_module_dir(void *id) {
  if (!g_ctx) return -1;

  size_t index = decode_module_id(id);
  if (index == SIZE_MAX) return -1;

  return rezygiskd_get_module_dir(index);
}

static uint32_t api_get_flags(void) {
  if (!g_ctx) return 0;

  return (g_ctx->info_flags & ~PRIVATE_MASK);
}

bool rezygisk_module_register(struct rezygisk_api *api, struct rezygisk_abi const *target_module) {
  if (!g_ctx || !api || !target_module || target_module->api_version > REZYGISK_API_VERSION) return false;

  LOGD("Registering module with API version %ld", target_module->api_version);

  size_t index = decode_module_id(api->impl);
  if (index == SIZE_MAX) return false;

  struct rezygisk_module *m = &zygisk_modules[index];
  m->abi = *target_module;
  m->api = *api;

  api->hook_jni_native_methods = hook_jni_methods;
  if (target_module->api_version >= 4) {
    api->plt_hook_register_v4 = api_plt_hook_register_v4;
    api->exempt_fd = api_exempt_fd;
    api->plt_hook_commit = api_plt_hook_commit_v4;
  } else {
    api->plt_hook_register = api_plt_hook_register;
    api->plt_hook_exclude = api_plt_hook_exclude;
    api->plt_hook_commit = api_plt_hook_commit;
  }

  api->connect_companion = api_connect_companion;
  api->set_option = api_set_option;

  if (target_module->api_version >= 2) {
    api->get_module_dir = api_get_module_dir;
    api->get_flags = api_get_flags;
  }

  return true;
}

/* INFO: Signal mask helper */
static int sigmask(int how, int signum) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, signum);

  return sigprocmask(how, &set, NULL);
}

static bool load_modules_only(void);

static void rz_fork_pre(struct zygisk_context *ctx) {
  /* INFO: Do our own fork before loading any 3rd party code.
              First block SIGCHLD, unblock after original fork is done.
  */
  sigmask(SIG_BLOCK, SIGCHLD);
  ctx->pid = old_fork();
  if (ctx->pid != 0 || FLAG_GET(ctx, SKIP_FD_SANITIZATION)) return;

  /* INFO: Record all open fds */
  DIR *dir = opendir("/proc/self/fd");
  if (!dir) {
    PLOGE("Failed to open /proc/self/fd");

    return;
  }

  struct dirent *entry;
  while ((entry = readdir(dir))) {
    int fd = parse_int(entry->d_name);
    if (fd < 0) continue;

    if (fd >= MAX_FD_SIZE) {
      close(fd);

      continue;
    }

    ctx->allowed_fds[fd] = 1;
  }

  /* INFO: The dirfd should not be allowed */
  int dfd = dirfd(dir);
  if (dfd >= 0 && dfd < MAX_FD_SIZE) ctx->allowed_fds[dfd] = 0;

  closedir(dir);
}

/* INFO: Marks every fd in `fdsArray` as allowed and hands back how many
         entries it held, so the caller that has to append to the array does not
         ask for the length a second time. Zero when there is no array. */
static jint mark_fds_allowed(struct zygisk_context *ctx, JNIEnv *env, jintArray fdsArray) {
  if (!fdsArray) return 0;

  jint *arr = (*env)->GetIntArrayElements(env, fdsArray, NULL);

  /* INFO: An allocation failure answers NULL, and the loop below would read the
            array through it on the fork path. Nothing is allowed rather than a
            crash, and the array is left alone - there is nothing to release.
            The length is taken before the elements for that reason: the caller
            that appends to the array needs it whether or not the contents could
            be read, and asking for it twice bought nothing. */
  jint len = (*env)->GetArrayLength(env, fdsArray);

  if (arr == NULL) {
    (*env)->ExceptionClear(env);

    return len;
  }

  for (jint i = 0; i < len; ++i) {
    int fd = arr[i];
    if (fd >= 0 && fd < MAX_FD_SIZE) ctx->allowed_fds[fd] = 1;
  }

  (*env)->ReleaseIntArrayElements(env, fdsArray, arr, JNI_ABORT);

  return len;
}

static void rz_sanitize_fds(struct zygisk_context *ctx) {
  if (FLAG_GET(ctx, SKIP_FD_SANITIZATION)) return;

  if (FLAG_GET(ctx, APP_FORK_AND_SPECIALIZE)) {
    jintArray fdsToIgnore = ctx->args.app->fds_to_ignore ? *ctx->args.app->fds_to_ignore : NULL;
    jint len = mark_fds_allowed(ctx, ctx->env, fdsToIgnore);

    if (ctx->exempted_fds_count > 0) {
      /* INFO: What is ours to keep is decided here, whatever happens to the
                framework's array below: the fds were exempted by a module,
                and our own close-walk must not take them even when the array
                they were meant to ride could not be built. */
      for (size_t i = 0; i < ctx->exempted_fds_count; i++) {
        int fd = ctx->exempted_fds[i];
        if (fd >= 0 && fd < MAX_FD_SIZE) ctx->allowed_fds[fd] = 1;
      }

      FLAG_SET(ctx, SKIP_FD_SANITIZATION);

      jintArray newArray = (*ctx->env)->NewIntArray(ctx->env, (jsize)(len + ctx->exempted_fds_count));
      if (newArray) {
        /* INFO: The original entries only stop being the answer once the
                  whole copy is known good: a failed read of the old array
                  would leave the zero-filled new one installed, and the
                  framework's sanitizer would then close fds it was told to
                  keep. */
        bool copied = true;

        if (fdsToIgnore && len > 0) {
          jint *arr = (*ctx->env)->GetIntArrayElements(ctx->env, fdsToIgnore, NULL);

          /* INFO: Same failure as above. The copied region is skipped rather
                    than read through a NULL, which would take the fork down
                    while it is only trying to exempt some fds. */
          if (arr != NULL) {
            (*ctx->env)->SetIntArrayRegion(ctx->env, newArray, 0, len, arr);
            (*ctx->env)->ReleaseIntArrayElements(ctx->env, fdsToIgnore, arr, JNI_ABORT);
          } else {
            (*ctx->env)->ExceptionClear(ctx->env);

            copied = false;
          }
        }

        (*ctx->env)->SetIntArrayRegion(ctx->env, newArray, len, (jsize)ctx->exempted_fds_count, ctx->exempted_fds);

        /* INFO: The pre-O argument variants have no fds_to_ignore to
                  replace - the pointer is NULL there - and writing through
                  it is a crash in the middle of specialize. The flags and
                  the allowed set above are the whole exemption on those
                  builds. */
        if (copied && ctx->args.app->fds_to_ignore != NULL) {
          *ctx->args.app->fds_to_ignore = newArray;

          (*ctx->env)->DeleteLocalRef(ctx->env, fdsToIgnore);
        } else if (!copied) {
          (*ctx->env)->DeleteLocalRef(ctx->env, newArray);

          LOGW("the framework's fd ignore list is kept: its copy could not be read");
        }
      } else {
        (*ctx->env)->ExceptionClear(ctx->env);

        LOGW("the exempted fds are only marked for our own walk: no array could be built for the framework's");
      }
    }
  }

  if (ctx->pid != 0) return;

  /* INFO: Close all forbidden fds to prevent crashing */
  DIR *dir = opendir("/proc/self/fd");
  if (!dir) {
    PLOGE("Failed to open /proc/self/fd");

    return;
  }

  int dfd = dirfd(dir);
  struct dirent *entry;
  while ((entry = readdir(dir))) {
    int fd = parse_int(entry->d_name);
    if (fd < 0 || fd >= MAX_FD_SIZE || fd == dfd || ctx->allowed_fds[fd]) continue;

    close(fd);

    LOGW("Closed leaked fd: %d", fd);
  }

  closedir(dir);
}

static void rz_fork_post(struct zygisk_context *ctx) {
  sigmask(SIG_UNBLOCK, SIGCHLD);

  /* INFO: Nothing of the parent's to give back. The process name is taken after
            the fork now, so only the child ever holds one and it hands it back
            in post-specialize; the release that used to stand here existed for
            an allocation the parent no longer makes. */
  (void) ctx;

  g_ctx = NULL;
}

static bool load_modules_only(void) {
  struct zygisk_modules ms;
  if (!rezygiskd_read_modules(&ms)) {
    LOGE("Failed to read modules from VexZygiskd");

    return false;
  }

  /* INFO: The daemon hands over its full slot range, empty paths standing for
            tombstoned slots (a module removed while zygotes already hold
            indexes into the list). Slots are kept aligned with the daemon's
            array - api.impl encodes the slot index, which is what
            RequestCompanionSocket and GetModuleDir are addressed with - so
            dead slots stay in place and are simply never called. */
  zygisk_module_length = 0;

  if (ms.modules_count == 0) {
    zygisk_modules = NULL;

    free_modules(&ms);

    return true;
  }

  zygisk_modules = (struct rezygisk_module *)calloc(ms.modules_count, sizeof(struct rezygisk_module));
  if (!zygisk_modules) {
    LOGE("Failed to allocate memory for modules");

    free_modules(&ms);

    return false;
  }

  /* INFO: The length is only allowed to grow past zero once the array exists:
            hook_unloader carries on when this load fails, and a non-zero
            length with a NULL array would crash the first fork in the module
            loop. */
  zygisk_module_length = ms.modules_count;

  /* INFO: Failure symmetry, reviewed: csoloader keeps no reference count,
            so a load that fails inside csoloader_load has mapped nothing and
            needs no release, while a library that loads but then misses its
            entry point is explicitly csoloader_unload'ed below — the same
            discipline the Zygisk Next path applies with dlclose. */
  for (size_t i = 0; i < ms.modules_count; i++) {
    const char *lib_path = ms.modules[i];

    if (lib_path == NULL || lib_path[0] == '\0') continue;

    if (!csoloader_load(&zygisk_modules[i].lib, lib_path)) {
      LOGE("Failed to load module [%s]", lib_path);

      /* INFO: In case a module failed to load, update the list of available modules
           in VexZygiskd to avoid a mismatch between the loaded modules in VexZygisk
           Zygote library and the available modules in VexZygiskd. The daemon
           tombstones in place, so the slot index needs no offset. */
      rezygiskd_remove_module(i);

      continue;
    }

    void *entry = csoloader_get_symbol(&zygisk_modules[i].lib, "zygisk_module_entry");
    if (!entry) {
      LOGE("Failed to find entry point in module [%s]", lib_path);

      csoloader_unload(&zygisk_modules[i].lib);

      rezygiskd_remove_module(i);

      continue;
    }

    zygisk_modules[i].api.register_module = rezygisk_module_register;
    zygisk_modules[i].api.impl = ENCODE_ID((void *)i);
    zygisk_modules[i].zygisk_module_entry = (void (*)(void *, void *))entry;

    LOGD("Loaded module [%s]. Entry: %p", lib_path, entry);

    zygisk_modules[i].unload = false;
  }

  free_modules(&ms);

  return true;
}

static void rz_run_modules_pre(struct zygisk_context *ctx) {
  for (size_t i = 0; i < zygisk_module_length; i++) {
    struct rezygisk_module *m = &zygisk_modules[i];

    /* INFO: A tombstoned slot is zeroed and carries no entry point. */
    if (m->zygisk_module_entry == NULL) continue;

    rz_module_call_on_load(m, ctx->env);

    if (FLAG_GET(ctx, APP_SPECIALIZE)) rz_module_call_pre_app_specialize(m, ctx->args.app);
    else if (FLAG_GET(ctx, SERVER_FORK_AND_SPECIALIZE)) rz_module_call_pre_server_specialize(m, ctx->args.server);
  }
}

static void rz_run_modules_post(struct zygisk_context *ctx) {
  FLAG_SET(ctx, POST_SPECIALIZE);

  size_t modules_unloaded = 0;
  for (size_t i = 0; i < zygisk_module_length; i++) {
    struct rezygisk_module *m = &zygisk_modules[i];

    if (m->zygisk_module_entry == NULL) continue;

    if (FLAG_GET(ctx, APP_SPECIALIZE)) rz_module_call_post_app_specialize(m, ctx->args.app);
    else if (FLAG_GET(ctx, SERVER_FORK_AND_SPECIALIZE)) rz_module_call_post_server_specialize(m, ctx->args.server);

    if (!m->unload) {
      LOGD("Abandoning module library at %p", &m->lib);

      csoloader_abandon(&m->lib);

      continue;
    }

    if (!csoloader_unload(&m->lib)) {
      LOGE("Failed to unload module library");

      continue;
    }

    modules_unloaded++;
  }

  if (zygisk_module_length > 0)
    LOGD("Modules unloaded: %zu/%zu", modules_unloaded, zygisk_module_length);
}

/* INFO: The UID sent to the daemon must be the app's, not an isolated
         service's: root implementations key off the app UID, so the isolated
         one would bypass the denylist. Third-party apps and their isolated
         processes always have app_data_dir; system apps may not, but they
         rarely spawn isolated processes. Returns false when the directory
         cannot be read, which abandons the specialization rather than sending
         the daemon a UID that would bypass the denylist. */
static bool resolve_app_uid(struct zygisk_context *ctx, uid_t *out_uid) {
  uid_t uid = *ctx->args.app->uid;

  if (IS_ISOLATED_SERVICE(uid) && ctx->args.app->app_data_dir) {
    /* INFO: If the app is an isolated service, we use the UID of the
               app's process data directory, which is the UID of the
               app itself, which root implementations actually use.
    */
    const char *data_dir = (*ctx->env)->GetStringUTFChars(ctx->env, *ctx->args.app->app_data_dir, NULL);
    if (!data_dir) {
      LOGE("Failed to get app data directory");

      return false;
    }

    struct stat st;
    if (stat(data_dir, &st) == -1) {
      PLOGE("Failed to stat app data directory [%s]", data_dir);

      (*ctx->env)->ReleaseStringUTFChars(ctx->env, *ctx->args.app->app_data_dir, data_dir);

      return false;
    }

    uid = st.st_uid;
    LOGD("Isolated service being related to UID %d, app data dir: %s", uid, data_dir);

    (*ctx->env)->ReleaseStringUTFChars(ctx->env, *ctx->args.app->app_data_dir, data_dir);
  }

  *out_uid = uid;

  return true;
}

/* INFO: The first process started is the reference for the clean namespace,
         captured before it does anything so the copy is clean yet keeps the
         expected mounts. Built in every mode, not only when the revert is
         off: the clean namespace is also what the webview zygote and every
         refused in-place revert fall back to, and building it lazily would
         let whichever process stumbles first donate its own mount tree as
         the reference for the rest of the boot. */
static void capture_clean_namespace(struct zygisk_context *ctx) {
  if ((ctx->info_flags & PROCESS_IS_FIRST_STARTED) != PROCESS_IS_FIRST_STARTED) return;
  if ((ctx->info_flags & PROCESS_ON_DENYLIST) == PROCESS_ON_DENYLIST) return;
  if ((ctx->info_flags & PROCESS_IS_MANAGER) == PROCESS_IS_MANAGER) return;

  update_mnt_ns(Clean, true);
}

/* INFO: Whether the name is an app zygote's. Android builds one process per
         package that declares zygotePreloadName, named "<package>_zygote", and
         WebView has its own, "webview_zygote": a process of its own that later
         forks its children through the zygote descriptor machinery instead of
         through the specialization path. */
static bool is_app_zygote_name(const char *process) {
  static const char suffix[] = "_zygote";
  const size_t suffix_len = sizeof(suffix) - 1;

  if (process == NULL) return false;

  const size_t len = strlen(process);
  if (len <= suffix_len) return false;

  return strcmp(process + len - suffix_len, suffix) == 0;
}

/* INFO: Hides the mounts of a process the denylist covers.

         An app zygote never gets the in-place revert, for two separate reasons
         and both of them fatal.

         The mount tree: it is the namespace every renderer and sandboxed
         process it later forks inherits for the whole uptime of the process,
         and running umount2 inside it detaches mounts its own mountinfo still
         names - an overlay that covers provider or framework resources then
         leaves the process resolving paths that no longer exist, which surfaces
         as broken WebView initialization and blank module WebUIs.

         The file descriptors: the copy this function makes belongs to the
         process alone, so the next unshare - the one zygote itself performs a
         few statements further into the same fork, in MountEmulatedStorage -
         leaves it with no member at all and the kernel tears it down,
         detaching every mount in it. Descriptors opened in between die with
         that tree: zygote points the zygote socket descriptors at /dev/null
         after the pre-specialize hooks have run, and once the mount behind them
         is detached their paths read back as "/null" rather than "/dev/null".
         Nothing notices until the process forks on its own, where zygote
         reopens every descriptor by path and refuses the ones its allowlist no
         longer matches - which is the app zygote of every Chromium-based
         browser aborting with "Not allowlisted (N): /null", and an app zygote
         that died is a browser with no sandboxed process, which is a browser
         with no network at all.

         So both are switched into the daemon's cached clean namespace instead,
         which never had the traces and is held by the daemon, so it outlives
         the unshare the fork performs.

         The private copy comes first for everyone else: unmounting without it
         would strip the traces out of the namespace the zygote sits in and
         every later fork would inherit that. A refused revert, or the mode
         being off, hides the process the namespace way instead - works as
         well, at the cost of one shared namespace. */
static void isolate_denylisted(struct zygisk_context *ctx, bool is_app_zygote) {
  FLAG_SET(ctx, DO_REVERT_UNMOUNT);

  if (is_app_zygote) {
    if (!update_mnt_ns(Clean, false)) {
      LOGE("Failed to switch the app zygote to the clean mount namespace");
    }

    return;
  }

  if (!revert_mode_enabled() || unshare(CLONE_NEWNS) == -1 || !revert_root_traces_here()) {
    update_mnt_ns(Clean, false);
  }
}

/* INFO: The Zygisk Next plan for the process being specialized.

         Modules are resolved per process: the zygote only ever loaded the ones
         targeting it, so an entry that names an application would stay dead
         otherwise. Every path that specializes a process asks here, always after
         the fd sanitizer - so the memfd and the companion sockets the load opens
         are not treated as leaked fds and closed - and after the mount namespace
         switch, so the daemon's handover is not lost to setns. Libraries
         inherited from the zygote are skipped inside the loader.

         Whether any Zygisk Next module exists is a daemon-wide fact, so the
         first flags answer is remembered and every later fork skips the round
         trip when there is nothing to resolve. */
static void zn_load_plan_for_specializing(const char *process_name) {
  if (zn_presence_known && !zn_modules_present) return;

  zn_load_modules_for_process(process_name);
}

static void rz_app_specialize_pre(struct zygisk_context *ctx) {
  FLAG_SET(ctx, APP_SPECIALIZE);

  uid_t uid;
  if (!resolve_app_uid(ctx, &uid)) return;

  ctx->info_flags = rezygiskd_get_process_flags(uid, ctx->process);

  /* INFO: Whether any Zygisk Next module exists is a daemon-wide fact, and the
            first flags answer is the only place it is learned. Unknown until
            that answer arrives - system_server is typically the very first
            fork - in which case the query still runs. */
  if (!zn_presence_known) {
    zn_modules_present = (ctx->info_flags & PROCESS_ZN_PRESENT) == PROCESS_ZN_PRESENT;
    zn_presence_known = true;
  }

  capture_clean_namespace(ctx);

  if ((ctx->info_flags & PROCESS_IS_MANAGER) == PROCESS_IS_MANAGER) {
    LOGD("Manager process detected. Notifying that Zygisk has been enabled.");

    /* INFO: Tells the root manager that Zygisk is working, so that it can be
               recognized as enabled and Zygisk modules work properly.
    */
    setenv("ZYGISK_ENABLED", "1", 1);
  }

  /* INFO: The mounts are updated before the modules run. In preSpecialize a
            module still has the privileges to mount/umount/setns, and updating
            the namespace afterwards would discard what it set up; by
            postSpecialize the namespace is already switched, so it is too
            late. Doing it first also lets modules touch denylisted processes
            without the change being reverted.

            WebView's app zygote is isolated even though the denylist never
            names it: it forks its sandboxed children outside the
            specialization path and hands them its own mount namespace, so left
            alone it keeps the root mount view while an isolated process gets
            the clean one, and two isolated processes then present different
            mount content. An app zygote the denylist does name is isolated for
            that same reason, and only then - one the denylist leaves alone
            keeps the mounts its own application keeps.

            Which of the two isolations an app zygote gets is decided lower
            down, in isolate_denylisted. */
  bool is_app_zygote = is_app_zygote_name(ctx->process);
  bool is_webview_zygote = ctx->process != NULL && strcmp(ctx->process, "webview_zygote") == 0;
  bool in_denylist = (ctx->info_flags & PROCESS_ON_DENYLIST) == PROCESS_ON_DENYLIST || is_webview_zygote;

  if (in_denylist) isolate_denylisted(ctx, is_app_zygote);

  /* INFO: Executed after setns to ensure a module can update the mounts of an
              application without worrying about it being overwritten by setns.
  */
  rz_run_modules_pre(ctx);

  /* INFO: The modules may request that although the process is NOT in
              the DenyList, it has its mount namespace switched to the clean
              one.

              So to ensure this behavior happens, we must also check after the
              modules are loaded and executed, so that the modules can have
              the chance to request it.
  */
  if (!in_denylist && FLAG_GET(ctx, DO_REVERT_UNMOUNT)) update_mnt_ns(Clean, false);
}

static void rz_app_specialize_post(struct zygisk_context *ctx) {
  rz_run_modules_post(ctx);

  /* INFO: Neither is a mount, so neither is reachable from the revert, and
            both are only final once the modules have run: the libraries they
            left mapped are known by then, and the mount table this process
            hands to the application is already the cleaned one.

            The condition is the revert flag and not the denylist bit: a module
            can ask for the same revert on a process the denylist does not
            name, and leaving that process's libraries and mount line behind
            would be half a hide - a clearer signal than either state alone. */
  if (FLAG_GET(ctx, DO_REVERT_UNMOUNT)) {
    refresh_mount_line();

    /* INFO: Nothing was loaded into this process, so the scan could only come
              back empty and it is the whole cost of asking. */
    if (zygisk_module_length > 0 || zn_loaded_library_count() > 0) hide_module_maps();
  }

  /* INFO: Allow the process name string to be released */
  (*ctx->env)->ReleaseStringUTFChars(ctx->env, *ctx->args.app->nice_name, ctx->process);
  g_ctx = NULL;
}

static void rz_nativeSpecializeAppProcess_pre(struct zygisk_context *ctx) {
  ctx->process = (*ctx->env)->GetStringUTFChars(ctx->env, *ctx->args.app->nice_name, NULL);
  if (ctx->process == NULL) {
    /* INFO: The same bail-out the fork path takes: continuing with a NULL
              name would reach strlen() in the daemon query, and the post
              below would release a pointer that was never handed out. The
              pending exception is ours to clear - it would abort the next
              JNI call in the specialize path otherwise. */
    (*ctx->env)->ExceptionClear(ctx->env);
    LOGW("Failed to read the process name, this process is specialized without us");

    return;
  }

  LOGV("pre specialize [%s]", ctx->process);

  FLAG_SET(ctx, SKIP_FD_SANITIZATION);

  /* INFO: This path specialises the calling process without a fork, so it is
             the caller that is the "child" here. Marking it is what lets
             is_zygote_child() tell that apart from a failed fork, which parks
             the same -1. */
  FLAG_SET(ctx, SPECIALIZE_IN_PLACE);

  rz_app_specialize_pre(ctx);
  zn_load_plan_for_specializing(ctx->process);
}

static void rz_nativeSpecializeAppProcess_post(struct zygisk_context *ctx) {
  /* INFO: Gated on the name: a pre that bailed out above never ran the
            module callbacks, so the post must not run them either - and the
            release inside would hand ART a NULL it is not required to take. */
  if (ctx->process == NULL) {
    g_ctx = NULL;

    return;
  }

  LOGV("post specialize [%s]", ctx->process);
  rz_app_specialize_post(ctx);
}

static void rz_nativeForkSystemServer_pre(struct zygisk_context *ctx) {
  LOGV("pre forkSystemServer");
  FLAG_SET(ctx, SERVER_FORK_AND_SPECIALIZE);

  /* INFO: system_server is left alone on purpose. It is the first child zygote
           forks and nothing hides it, so it keeps the module tree the framework
           expects: KernelSU's meta-module mechanism hangs Zygisk and
           framework-level content off those very mounts. Nothing here has to
           special-case it, because the revert only ever runs on a denylisted
           process, on that process's own copy of the mount tree. */
  rz_fork_pre(ctx);
  if (!is_zygote_child(ctx)) return;

  rz_run_modules_pre(ctx);

  rz_sanitize_fds(ctx);

  zn_load_plan_for_specializing("system_server");
}

static void rz_nativeForkSystemServer_post(struct zygisk_context *ctx) {
  if (ctx->pid == 0) {
    LOGV("post forkSystemServer");

    rz_run_modules_post(ctx);
  }

  rz_fork_post(ctx);
}

static void rz_nativeForkAndSpecialize_pre(struct zygisk_context *ctx) {
  FLAG_SET(ctx, APP_FORK_AND_SPECIALIZE);

  /* INFO: Deliberately no revert here. Stripping the mounts out of the zygote
           would strip them out of every later fork too, including the apps
           that are meant to keep them - a metamodule's themes and overlays
           among them. The revert runs per denylisted process from
           rz_app_specialize_pre instead, on that process's own copy of the
           mount tree. */
  rz_fork_pre(ctx);
  if (!is_zygote_child(ctx)) return;

  /* INFO: The name is read here, after the fork, and only here. Both halves
            used to take it - the parent's copy existed only to be handed back
            in rz_fork_post - so the zygote paid one JNI allocation, one pinned
            string and one release per process it spawned, for a value only the
            child ever reads: the daemon query, the webview check and the module
            plan are all below this line. */
  ctx->process = (*ctx->env)->GetStringUTFChars(ctx->env, *ctx->args.app->nice_name, NULL);
  if (ctx->process == NULL) {
    LOGW("Failed to read the process name, this process is specialized without us");

    return;
  }

  rz_app_specialize_pre(ctx);
  rz_sanitize_fds(ctx);

  zn_load_plan_for_specializing(ctx->process);
}

static void rz_nativeForkAndSpecialize_post(struct zygisk_context *ctx) {
  /* INFO: Gated on the name and not the pid: a first fork that failed parks
            pid at -1 and the pre returns before the name is read, but the
            framework's own fork then succeeds through the new_fork hook and
            sets pid to 0 - a post that keyed on that alone would run module
            post-callbacks whose pre never ran, and release a NULL name. */
  if (ctx->pid == 0 && ctx->process != NULL) {
    LOGV("post forkAndSpecialize [%s]", ctx->process);
    rz_app_specialize_post(ctx);
  } else if (ctx->pid == 0) {
    g_ctx = NULL;
  }

  rz_fork_post(ctx);
}

static void rz_init(struct zygisk_context *ctx, JNIEnv *env, void *args) {
  spawn_pipeline_enter();

  /* INFO: Only what is read before it is written is cleared. The two hook
            tables and the exempted-fd list are walked up to their counts, so a
            slot that was never written is never read and only the counts need
            clearing; allowed_fds is a bitmap with no count and does have to be
            cleared whole. The structure used to be zeroed entire, which is
            some eleven kilobytes of regex_t tables on a frame the injection
            path has just taken out of its stack. */
  memset(ctx->allowed_fds, 0, sizeof(ctx->allowed_fds));
  ctx->flags = 0;
  ctx->info_flags = 0;
  ctx->process = NULL;
  ctx->exempted_fds_count = 0;
  ctx->register_info_count = 0;
  ctx->ignore_info_count = 0;

  ctx->env = env;
  ctx->args.ptr = args;
  ctx->pid = -1;
  pthread_mutex_init(&ctx->hook_info_lock, NULL);

  g_ctx = ctx;
}

static void rz_cleanup(struct zygisk_context *ctx) {
  g_ctx = NULL;

  /* INFO: The pipeline is over as far as the process-global state is
            concerned; parent and child each release their own copy of the
            semaphore here (the child inherited it mid-pipeline). */
  spawn_pipeline_leave();

  if (!is_zygote_child(ctx)) return;

  hooks_removed = true;

  /* INFO: Unhook JNI methods. A class whose originals could not be
            re-registered is logged and left hooked - the hook stubs live in
            this library, which stays mapped (hidden, not gone) - because the
            alternative was worse: recording the failure used to stop the
            whole teardown below, leaving the library named in the maps and
            the PLT hooks in place for the lifetime of the process. */
  for (size_t i = 0; i < jni_hook_list_count; i++) {
    struct jni_hook_entry *entry = &jni_hook_list[i];
    jclass jc = (*ctx->env)->FindClass(ctx->env, entry->class_name);
    if (jc) {
      if (entry->methods_count > 0 && (*ctx->env)->RegisterNatives(ctx->env, jc, entry->methods, (jint)entry->methods_count) != 0) {
        LOGE("Failed to restore JNI hook of class [%s]", entry->class_name);

        (*ctx->env)->ExceptionClear(ctx->env);
      }

      (*ctx->env)->DeleteLocalRef(ctx->env, jc);
    }

    free(entry->class_name);
    free(entry->methods);
  }

  free(jni_hook_list);
  jni_hook_list = NULL;
  jni_hook_list_count = 0;

  clear_hook_info(ctx);

  free_plt_hook_list();

  /* INFO: And the table the registrations shared goes with them: nothing will
            ask for a hook again in this process, and holding a table that
            describes a process that has since moved on is how a stale answer
            gets handed to whoever asks next. */
  plt_hook_forget_maps();

  /* INFO: Strip out all API function pointers */
  for (size_t i = 0; i < zygisk_module_length; i++) {
    memset(&zygisk_modules[i], 0, sizeof(zygisk_modules[i]));
  }
  zygisk_module_length = 0;

  enable_unloader = true;
  pthread_mutex_destroy(&ctx->hook_info_lock);
}

/* INFO: One PLT hook, added and removed through the macros below. The
         "commit" that actually applies a batch is api_plt_hook_commit (and its
         v4 form) further up; this pair is the per-symbol half. */
static bool hook_register(const char *lib_name, const char *symbol, bool is_prefix, void *new_func, void **backup) {
  if (!(is_prefix ? plti_add_hook_by_prefix : plti_add_hook)(&plti_ctx, lib_name, symbol, new_func, backup)) {
    LOGE("Failed to register plt_hook \"%s\" with PLTI", symbol);

    return false;
  }

  LOGD("Registered plt_hook for symbol \"%s\" in library \"%s\"", symbol, lib_name);

  return true;
}

static bool hook_unregister(const char *lib_name, const char *symbol, bool is_prefix, void **backup) {
  if (!(is_prefix ? plti_remove_hook_by_prefix : plti_remove_hook)(&plti_ctx, lib_name, symbol, backup)) {
    LOGE("Failed to unregister plt_hook \"%s\" with PLTI", symbol);

    hooks_removed = false;

    return false;
  }

  LOGD("Unregistered plt_hook for symbol \"%s\" in library \"%s\"", symbol, lib_name);

  return true;
}

#define PLT_HOOK_REGISTER_SYM(LIB, SYM, NAME, IS_PREFIX)                       \
  hook_register(LIB, SYM, IS_PREFIX, (void *)new_##NAME, (void **)&old_##NAME)

#define PLT_HOOK_REGISTER(LIB, SYM, IS_PREFIX)     \
  PLT_HOOK_REGISTER_SYM(LIB, #SYM, SYM, IS_PREFIX)

#define PLT_HOOK_UNREGISTER_SYM(LIB, SYM, NAME, IS_PREFIX)   \
  hook_unregister(LIB, SYM, IS_PREFIX, (void **)&old_##NAME)

#define PLT_HOOK_UNREGISTER(LIB, SYM, IS_PREFIX)     \
  PLT_HOOK_UNREGISTER_SYM(LIB, #SYM, SYM, IS_PREFIX)

void hook_functions(void) {
  if (!plti_init(&plti_ctx)) {
    LOGE("Failed to initialize PLTI");

    return;
  }

  if (!plti_add_lib(&plti_ctx, "libandroid_runtime.so")) {
    LOGE("Failed to add libandroid_runtime.so to PLTI");

    return;
  }

  /* INFO: Each result is logged rather than checked, because nothing here
            can undo a partial setup: the four are one batch, and the loader
            still has to run with whichever ones took. */
  if (!PLT_HOOK_REGISTER("libandroid_runtime.so", fork, false))
    LOGE("Failed to hook fork in libandroid_runtime.so");
  if (!PLT_HOOK_REGISTER("libandroid_runtime.so", strdup, false))
    LOGE("Failed to hook strdup in libandroid_runtime.so");
  if (!PLT_HOOK_REGISTER("libandroid_runtime.so", property_get, false))
    LOGE("Failed to hook property_get in libandroid_runtime.so");
  if (!PLT_HOOK_REGISTER_SYM("libandroid_runtime.so", "_ZNK18FileDescriptorInfo14ReopenOrDetach", _ZNK18FileDescriptorInfo14ReopenOrDetach, true))
    LOGE("Failed to hook FileDescriptorInfo::ReopenOrDetach in libandroid_runtime.so");
}

static void hook_unloader(void) {
  /* INFO: Run the expensive setup (PLT unregister + module load) at most once,
           but keep retrying until every piece of it has taken: the first
           property_get calls can land before the runtime is loaded, in which
           case plti_add_lib fails and a later call tries again.

           The module load retries on the same trigger. A load that fails
           against a busy daemon during a boot burst used to be final, and
           classic modules then never loaded in this zygote or in any process
           it forked, for the whole boot - which read, from the outside, as
           "Zygisk randomly does not work today". load_modules_only answers
           false only before it has loaded anything, so a retry starts clean.

           The in-progress flag keeps the retries single-threaded: a module
           that calls property_get while it is loading would otherwise re-
           enter this setup around itself. */
  static bool installed = false;
  static bool in_progress = false;
  static bool libart_added = false;
  if (installed || in_progress) return;

  in_progress = true;

  if (!libart_added) {
    if (!plti_add_lib(&plti_ctx, "libart.so")) {
      LOGE("Failed to add libart.so to PLTI, retrying on a later property_get");

      in_progress = false;

      return;
    }

    libart_added = true;
  }

  /* INFO: A registration that did not take is not a reason to tear the
            property_get trigger down: unhooking it here would leave no later
            call to retry on, and the unloader would never fire for the rest
            of this zygote's life. property_get stays hooked until the
            registration succeeds. */
  if (!PLT_HOOK_REGISTER("libart.so", pthread_attr_setstacksize, false)) {
    LOGE("Failed to hook pthread_attr_setstacksize, retrying on a later property_get");

    in_progress = false;

    return;
  }

  /* INFO: Loaded before the trigger is unhooked, for the same reason: a
            failed load needs a later call to retry on, and this is the only
            trigger there is. */
  if (!load_modules_only()) {
    LOGE("Failed to load modules, retrying on a later property_get");

    in_progress = false;

    return;
  }

  PLT_HOOK_UNREGISTER("libandroid_runtime.so", property_get, false);

  installed = true;
  in_progress = false;

  LOGD("VexZygisk unloader hooked successfully");
}

static void unhook_functions(void) {
  PLT_HOOK_UNREGISTER("libandroid_runtime.so", fork, false);
  PLT_HOOK_UNREGISTER("libandroid_runtime.so", strdup, false);
  PLT_HOOK_UNREGISTER_SYM("libandroid_runtime.so", "_ZNK18FileDescriptorInfo14ReopenOrDetach", _ZNK18FileDescriptorInfo14ReopenOrDetach, true);
  PLT_HOOK_UNREGISTER("libart.so", pthread_attr_setstacksize, false);
}
