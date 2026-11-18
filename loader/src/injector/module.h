#ifndef MODULE_H
#define MODULE_H

#include <string.h>

#include <jni.h>

#include <csoloader.h>

#include "logging.h"

#define REZYGISK_API_VERSION 5

/* INFO: Plain macros rather than a typed enum: 1u << 31 does not fit an int,
         and a fixed underlying type is a C23 extension. */
#define PROCESS_GRANTED_ROOT (1u << 0)
#define PROCESS_ON_DENYLIST (1u << 1)

#define PROCESS_IS_MANAGER (1u << 27)
#define PROCESS_ROOT_IS_APATCH (1u << 28)
#define PROCESS_ROOT_IS_KSU (1u << 29)
#define PROCESS_IS_FIRST_STARTED (1u << 31)

/* INFO: PRIVATE_MASK strips everything a Zygisk module must not see from
         the flags the API hands out. */
#define PRIVATE_MASK PROCESS_IS_FIRST_STARTED

struct app_specialize_args_v1 {
  jint *uid;
  jint *gid;
  jintArray *gids;
  jint *runtime_flags;
  jint *mount_external;
  jstring *se_info;
  jstring *nice_name;
  jstring *instruction_set;
  jstring *app_data_dir;

  jboolean *is_child_zygote;
  jboolean *is_top_app;
  jobjectArray *pkg_data_info_list;
  jobjectArray *whitelisted_data_info_list;
  jboolean *mount_data_dirs;
  jboolean *mount_storage_dirs;
};

struct app_specialize_args_v4 {
  jint *uid;
  jint *gid;
  jintArray *gids;
  jint *runtime_flags;
  jobjectArray *rlimits;
  jint *mount_external;
  jstring *se_info;
  jstring *nice_name;
  jstring *instruction_set;
  jstring *app_data_dir;

  jintArray *fds_to_ignore;
  jboolean *is_child_zygote;
  jboolean *is_top_app;
  jobjectArray *pkg_data_info_list;
  jobjectArray *whitelisted_data_info_list;
  jboolean *mount_data_dirs;
  jboolean *mount_storage_dirs;
};

struct app_specialize_args_v5 {
  jint *uid;
  jint *gid;
  jintArray *gids;
  jint *runtime_flags;
  jobjectArray *rlimits;
  jint *mount_external;
  jstring *se_info;
  jstring *nice_name;
  jstring *instruction_set;
  jstring *app_data_dir;

  jintArray *fds_to_ignore;
  jboolean *is_child_zygote;
  jboolean *is_top_app;
  jobjectArray *pkg_data_info_list;
  jobjectArray *whitelisted_data_info_list;
  jboolean *mount_data_dirs;
  jboolean *mount_storage_dirs;

  jboolean *mount_sysprop_overrides;
};

struct server_specialize_args_v1 {
  jint *uid;
  jint *gid;
  jintArray *gids;
  jint *runtime_flags;
  jlong *permitted_capabilities;
  jlong *effective_capabilities;
};

enum rezygisk_options {
  /* INFO: Force VexZygisk to umount the root related mounts on this process. This option
             will only take effect if set in pre...Specialize, as VexZygisk umounts at
             that point.

           VexZygisk Umount System will not umount all root related mounts, read VexZygiskd
             detach_root_mounts function in utils.c file to understand how it selects the ones
             to detach.
  */
  FORCE_DENYLIST_UNMOUNT = 0,

  /* INFO: Once set, VexZygisk will dlclose your library from the process, this is assured to
             happen after post...Specialize, but not at a specific moment due to different
             implementations.

           You should not use this option if you leave references in the process such as hooks,
             which will try to execute uninitialized memory.
  */
  DLCLOSE_MODULE_LIBRARY = 1
};

struct rezygisk_abi {
  long api_version;
  void *impl;

  void (*pre_app_specialize)(void *, void *);
  void (*post_app_specialize)(void *, const void *);
  void (*pre_server_specialize)(void *, void *);
  void (*post_server_specialize)(void *, const void *);
};

struct rezygisk_api {
  void *impl;
  bool (*register_module)(struct rezygisk_api *, struct rezygisk_abi const *);

  void (*hook_jni_native_methods)(JNIEnv *, const char *, JNINativeMethod *, int);
  union {
    void (*plt_hook_register)(const char *, const char *, void *, void **);    /* INFO: v3 and below */
    void (*plt_hook_register_v4)(dev_t, ino_t, const char *, void *, void **); /* INFO: v4 */
  };
  union {
    void (*plt_hook_exclude)(const char *, const char *); /* INFO: v3 and below */
    void (*exempt_fd)(int);                               /* INFO: v4 */
  };

  bool (*plt_hook_commit)();
  int (*connect_companion)(void *);
  void (*set_option)(void *, enum rezygisk_options opt);
  int (*get_module_dir)(void *);
  uint32_t (*get_flags)();
};

struct rezygisk_module {
  struct rezygisk_abi abi;
  struct rezygisk_api api;

  struct csoloader lib;
  void (*zygisk_module_entry)(void *, void *);

  bool unload;
};

/* The function bodies below are inline so every includer may have its own copy
   (ODR); a body in a header otherwise risks duplicate definitions.

   NOTE: The original Zygisk API expects every module to implement all of the
         specialize callbacks, and Magisk's Zygisk dereferences them without a
         NULL check, so each wrapper below skips the module rather than calling
         into a missing entry point. The name the skip warnings print goes
         through module_name(): a slot that never finished loading has no image
         to name. */
static inline const char *module_name(struct rezygisk_module *m) {
  return m->lib.img != NULL && m->lib.img->elf != NULL ? m->lib.img->elf : "<unloaded module>";
}

static inline void rz_module_call_on_load(struct rezygisk_module *m, void *env) {
  m->zygisk_module_entry((void *)&m->api, env);
}

static inline void rz_module_call_pre_app_specialize(struct rezygisk_module *m, struct app_specialize_args_v5 *args) {
  if (!m->abi.pre_app_specialize) {
    /* NOTE: See the header block above on Magisk's missing callback check. */
    LOGW("Module [%s] doesn't have pre_app_specialize. Skipping it.", module_name(m));

    return;
  }

  switch (m->abi.api_version) {
    case 1:
    case 2: {
      struct app_specialize_args_v1 versioned_args = {
        .uid = args->uid,
        .gid = args->gid,
        .gids = args->gids,
        .runtime_flags = args->runtime_flags,
        .mount_external = args->mount_external,
        .se_info = args->se_info,
        .nice_name = args->nice_name,
        .instruction_set = args->instruction_set,
        .app_data_dir = args->app_data_dir,
        .is_child_zygote = args->is_child_zygote,
        .is_top_app = args->is_top_app,
        .pkg_data_info_list = args->pkg_data_info_list,
        .whitelisted_data_info_list = args->whitelisted_data_info_list,
        .mount_data_dirs = args->mount_data_dirs,
        .mount_storage_dirs = args->mount_storage_dirs
      };

      m->abi.pre_app_specialize(m->abi.impl, &versioned_args);

      break;
    }
    case 3:
    case 4: {
      struct app_specialize_args_v4 versioned_args;
      memcpy(&versioned_args, args, sizeof(struct app_specialize_args_v4));

      m->abi.pre_app_specialize(m->abi.impl, &versioned_args);

      break;
    }
    case 5: {
      m->abi.pre_app_specialize(m->abi.impl, args);

      break;
    }
  }
}

static inline void rz_module_call_post_app_specialize(struct rezygisk_module *m, const struct app_specialize_args_v5 *args) {
  if (!m->abi.post_app_specialize) {
    /* NOTE: See the header block above on Magisk's missing callback check. */
    LOGW("Module [%s] doesn't have post_app_specialize. Skipping it.", module_name(m));

    return;
  }

  switch (m->abi.api_version) {
    case 1:
    case 2: {
      struct app_specialize_args_v1 versioned_args = {
        .uid = args->uid,
        .gid = args->gid,
        .gids = args->gids,
        .runtime_flags = args->runtime_flags,
        .mount_external = args->mount_external,
        .se_info = args->se_info,
        .nice_name = args->nice_name,
        .instruction_set = args->instruction_set,
        .app_data_dir = args->app_data_dir,
        .is_child_zygote = args->is_child_zygote,
        .is_top_app = args->is_top_app,
        .pkg_data_info_list = args->pkg_data_info_list,
        .whitelisted_data_info_list = args->whitelisted_data_info_list,
        .mount_data_dirs = args->mount_data_dirs,
        .mount_storage_dirs = args->mount_storage_dirs
      };

      m->abi.post_app_specialize(m->abi.impl, &versioned_args);

      break;
    }
    case 3:
    case 4: {
      struct app_specialize_args_v4 versioned_args;
      memcpy(&versioned_args, args, sizeof(struct app_specialize_args_v4));

      m->abi.post_app_specialize(m->abi.impl, &versioned_args);

      break;
    }
    case 5: {
      m->abi.post_app_specialize(m->abi.impl, args);

      break;
    }
  }
}

static inline void rz_module_call_pre_server_specialize(struct rezygisk_module *m, struct server_specialize_args_v1 *args) {
  if (!m->abi.pre_server_specialize) {
    /* NOTE: See the header block above on Magisk's missing callback check. */
    LOGW("Module [%s] doesn't have pre_server_specialize. Skipping it.", module_name(m));

    return;
  }

  m->abi.pre_server_specialize(m->abi.impl, args);
}

static inline void rz_module_call_post_server_specialize(struct rezygisk_module *m, const struct server_specialize_args_v1 *args) {
  if (!m->abi.post_server_specialize) {
    /* NOTE: See the header block above on Magisk's missing callback check. */
    LOGW("Module [%s] doesn't have post_server_specialize. Skipping it.", module_name(m));

    return;
  }

  m->abi.post_server_specialize(m->abi.impl, args);
}

#endif /* MODULE_H */
