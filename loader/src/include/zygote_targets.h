#ifndef ZYGOTE_TARGETS_H
#define ZYGOTE_TARGETS_H

/* What the monitor injects, how it weighs a re-exec, and how the injector
   recognises an app zygote.

   These are pure string comparisons, and each of them has been wrong once: a
   device whose host binary is not the classic one was never injected at all, and
   an app zygote taken for an ordinary application took the in-place revert into
   a mount namespace everything below it inherits. Being pure is also what makes
   them testable without a device (tests/host/test_zygote_targets.c). */

#include <stdbool.h>
#include <string.h>

/* The executables that host Android's application runtime, and so the processes
   the monitor exists to inject.

   app_process64 is the classic one. Android 15 moved the ART host into the ART
   APEX, where the same role is carried by artd. Knowing only the first spelling
   meant such a device was never injected at all. An exec of anything else is
   left to whichever monitor owns it. */
#define APP_PROCESS_NAME "/system/bin/app_process64"
#define ART_DAEMON_NAME "/apex/com.android.art/bin/artd"

static inline bool zygote_program_is_app_host(const char *program) {
  return strcmp(program, APP_PROCESS_NAME) == 0 || strcmp(program, ART_DAEMON_NAME) == 0;
}

/* Whether an exec of this program counts towards the crash-loop stop.

   Only the classic binary does. The ART daemon execs on its own schedule for its
   own reasons, and counting those would shut injection off the first time it did
   so a few times in a row. */
static inline bool zygote_program_counts_as_restart(const char *program) {
  return strcmp(program, APP_PROCESS_NAME) == 0;
}

/* Whether the process name is an app zygote's. Android builds one process per
   package that declares zygotePreloadName, named "<package>_zygote", and WebView
   has its own, "webview_zygote": a process that later forks its children through
   the zygote descriptor machinery instead of the specialization path. */
static inline bool zygote_process_is_app_zygote(const char *process) {
  static const char suffix[] = "_zygote";
  const size_t suffix_len = sizeof(suffix) - 1;

  if (process == NULL) return false;

  const size_t len = strlen(process);
  if (len <= suffix_len) return false;

  return strcmp(process + len - suffix_len, suffix) == 0;
}

#endif /* ZYGOTE_TARGETS_H */
