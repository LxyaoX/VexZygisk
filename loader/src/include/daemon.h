#ifndef DAEMON_H
#define DAEMON_H

#include <stdbool.h>
#include <stdint.h>

#include "zygisk_paths.h"

#include <unistd.h>

/* Spacing of unproductive connection attempts. Short by default: the socket is
   accepted at once or refused outright, so a longer wait only stalls every
   injection while the daemon is down, and this still rides out a restart. */
#define REZYGISKD_RETRY_DELAY_US 100000

/* Must stay in step with enum DaemonSocketAction on the daemon. */
enum rezygiskd_actions {
  ZygoteInjected,
  GetProcessFlags,
  GetInfo,
  ReadModules,
  RequestCompanionSocket,
  GetModuleDir,
  ZygoteRestart,
  UpdateMountNamespace,
  RemoveModule,
  ReadZnModules,
  SpawnZnCompanion
};

struct zygisk_modules {
  char **modules;
  size_t modules_count;
};

/* A Zygisk Next library as the daemon hands it over: the path it was resolved
   from, its module, whether that module asked for a companion, and the fd. */
struct zn_module_file {
  char *lib_path;
  char *module_id;
  bool companion;
  int fd;
};

/* Only the matching member is compiled in. Its name deliberately differs from
   the ROOT_IMPL_APATCH macro that selects it: a -D would expand the enumerator
   to 1. */
#ifdef ROOT_IMPL_APATCH
enum root_impl {
  ROOT_APATCH
};
#else
enum root_impl {
  ROOT_KERNELSU
};
#endif

struct rezygisk_info {
  struct zygisk_modules modules;
  enum root_impl root_impl;
  pid_t pid;
  bool running;
};

/* The loader only ever needs the clean namespace: a denylisted process is
   switched into it when the in-place revert could not be applied. */
enum mount_namespace_state {
  Clean
};

bool rezygiskd_zygote_injected(void);

uint32_t rezygiskd_get_process_flags(uid_t uid, const char *const process);

void rezygiskd_get_info(struct rezygisk_info *info);

void free_rezygisk_info(struct rezygisk_info *info);

bool rezygiskd_read_modules(struct zygisk_modules *modules);

void free_modules(struct zygisk_modules *modules);

/* Asks for the Zygisk Next libraries targeting this process. False when the
   daemon cannot be reached, which is the signal to read the modules directly.
   `retry` is the number of extra attempts, so the call makes retry + 1 and
   waits at most retry * retry_delay_us. */
bool rezygiskd_read_zn_modules(const char *process_name, const char *process_path, uint8_t retry, uint32_t retry_delay_us, struct zn_module_file **out, size_t *out_len);

void free_zn_module_files(struct zn_module_file *files, size_t len);

/* Has the daemon spawn a companion for this library; returns its control
   socket, or -1 when it is unavailable. */
int rezygiskd_spawn_zn_companion(const char *lib_path);

int rezygiskd_connect_companion(size_t index);

int rezygiskd_get_module_dir(size_t index);

void rezygiskd_zygote_restart(void);

bool rezygiskd_update_mns(enum mount_namespace_state nms_state, char *buf, size_t buf_size);

bool rezygiskd_remove_module(size_t index);

#endif /* DAEMON_H */
