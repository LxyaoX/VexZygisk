#include <stdlib.h>
#include <string.h>

#include <stdio.h>

#include "root_impl/common.h"
#include "companion.h"
#include "zygiskd.h"

#include "utils.h"

/* INFO: Both companion entry points take their control descriptor as argv[2]
         and validate it identically: anything outside a plausible descriptor
         range is a usage error, not something to hand to the kernel. */
static int parse_companion_fd(const char *arg, int *out_fd) {
  char *end = NULL;
  long parsed = strtol(arg, &end, 10);
  if (end == arg || *end != '\0' || parsed < 0 || parsed > 4095) {
    LOGI("Invalid descriptor number: %s", arg);

    return 1;
  }

  *out_fd = (int)parsed;

  return 0;
}

int main(int argc, char *argv[]) {
  /* INFO: stdout is the module script's pipe, drained into the root
            manager's log. The daemon is long-lived and logs to logd, so the
            pipe side channel is cut before anything logs: in debug builds
            every printf becomes a null write, and release ones compile away
            entirely. Companions are execed from here and inherit it. A failed
            redirect just leaves the inherited stdout in place - logd output
            is unaffected either way. */
  (void) freopen("/dev/null", "w", stdout);

  LOGI("Welcome to VexZygiskd");

  if (argc > 1) {
    if (strcmp(argv[1], "companion") == 0) {
      if (argc < 3) {
        LOGI("Usage: zygiskd companion <fd>");

        return 1;
      }

      int fd;
      if (parse_companion_fd(argv[2], &fd) != 0) return 1;

      companion_entry(fd);

      return 0;
    } else if (strcmp(argv[1], "version") == 0) {
      LOGI("VexZygisk Daemon %s", ZKSU_VERSION);

      return 0;
    } else if (strcmp(argv[1], "root") == 0) {
      root_impls_setup();

      struct root_impl impl;
      get_impl(&impl);

      char impl_name[LONGEST_ROOT_IMPL_NAME];
      stringify_root_impl_name(impl, impl_name);

      LOGI("Root implementation: %s", impl_name);

      return 0;
    } else {
      LOGI("Usage: zygiskd [companion|version|root]");

      return 0;
    }
  }

  if (switch_mount_namespace(1) == false) {
    LOGE("Failed to switch mount namespace");

    return 1;
  }
  root_impls_setup();
  zygiskd_start(argv);

  return 0;
}
