#ifndef UTILS_H
#define UTILS_H

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <android/log.h>

#include "constants.h"
#include "root_impl/common.h"

#include "socket_protocol.h"

/* Duplicated rather than pulled from the loader's shared header: utils.h is the
   only header the daemon's sources share, and reaching into the loader's tree
   would drag the host tests along. */
#define APP_ID(uid) ((uid) % 100000)

/* The identity a cached verdict is invalidated on. One comparison, so a change
   to what counts as the same file cannot reach one caller and miss the others. */
static inline bool stat_identity_same(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev &&
         a->st_ino == b->st_ino &&
         a->st_size == b->st_size &&
         a->st_mtime == b->st_mtime;
}

#ifndef LOG_TAG
  #define LOG_TAG "zygiskd"
#endif

/* Release builds are completely silent: every level compiles away under
   NDEBUG. Debug packages keep the full output. */
#ifdef NDEBUG
  #define LOGD(...) do { } while (0)
  #define LOGI(...) do { } while (0)
  #define LOGW(...) do { } while (0)
  #define LOGE(...) do { } while (0)
#else
  #define LOGD(...)                                              \
    do {                                                         \
      __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__); \
      printf(__VA_ARGS__);                                       \
    } while (0)

  #define LOGI(...)                                              \
    do {                                                         \
      __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); \
      printf(__VA_ARGS__);                                       \
    } while (0)

  #define LOGW(...)                                              \
    do {                                                         \
      __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__); \
      printf(__VA_ARGS__);                                       \
    } while (0)

  #define LOGE(...)                                              \
    do {                                                         \
      __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__); \
      printf(__VA_ARGS__);                                       \
    } while (0)
#endif

/* Fixed-argument: a variadic PLOGE("read") would pass an empty __VA_ARGS__,
   which -Wpedantic rejects. */
#define PLOGE(msg) LOGE("%s: %s", (msg), strerror(errno))

/* Not wrapped in do { } while (0): the on_fail argument is instantiated with
   break, continue or goto, whose meaning the loop would swallow. */
#define ASSURE_SIZE_WRITE(area_name, subarea_name, sent_size, expected_size, return_type)                        \
  if (sent_size != (ssize_t)(expected_size)) {                                                                   \
    LOGE("Failed to sent " subarea_name " in " area_name ": Expected %zu, got %zd\n", expected_size, sent_size); \
                                                                                                                 \
    return_type;                                                                                                 \
  }

#define ASSURE_SIZE_READ(area_name, subarea_name, sent_size, expected_size, return_type)                         \
  if (sent_size != (ssize_t)(expected_size)) {                                                                   \
    LOGE("Failed to read " subarea_name " in " area_name ": Expected %zu, got %zd\n", expected_size, sent_size); \
                                                                                                                 \
    return_type;                                                                                                 \
  }

bool switch_mount_namespace(pid_t pid);

void set_socket_create_context(const char *restrict context);

void unix_datagram_sendto(const char *restrict path, const void *restrict buf, size_t len);

int chcon(const char *path, const char *restrict context);

int unix_listener_from_path(const char *path);

ssize_t read_string(int fd, char *restrict buf, size_t buf_size);

bool check_unix_socket(int fd, bool block);

void stringify_root_impl_name(struct root_impl impl, char *restrict output);

int save_mns_fd(int pid);

#endif /* UTILS_H */
