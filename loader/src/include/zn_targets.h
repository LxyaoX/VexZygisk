#ifndef ZN_TARGETS_H
#define ZN_TARGETS_H

/* The zygote-class target names of zn_modules.txt. It lives in the loader's
   include tree because that is where the two halves of the protocol meet, not
   because the loader matches them: the daemon is the only source of the plan. */

#include <string.h>

static inline bool zn_target_is_zygote_class(const char *target) {
  return strcmp(target, "zygote") == 0 ||
         strcmp(target, "zygote64") == 0 ||
         strcmp(target, "zygote32") == 0 ||
         strcmp(target, "hyos_spawner") == 0;
}

/* The processes a zygote-class target names. artd is where Android 15 moved the
   runtime host, so a target meaning "the process applications come from" has to
   reach it. The first three match by substring on purpose - the platform spells
   them with build-dependent suffixes - while artd matches exactly, being short
   enough that a substring would start naming other processes. */
static inline bool zn_process_is_zygote_class(const char *process_name) {
  return strstr(process_name, "zygote") != NULL ||
         strstr(process_name, "app_process") != NULL ||
         strstr(process_name, "hyos_spawner") != NULL ||
         strcmp(process_name, "artd") == 0;
}

#endif /* ZN_TARGETS_H */
