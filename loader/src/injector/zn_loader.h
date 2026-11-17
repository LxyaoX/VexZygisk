#ifndef ZN_LOADER_H
#define ZN_LOADER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The extra daemon connection attempts entry() gives the module plan before it
   gives up. entry() runs once per target, and a zygote's apps ask again for
   themselves, so what it can lose is only the modules naming the zygote. Three
   attempts ride out a daemon still coming up without holding a boot on one that
   never answers; they only elapse while the daemon is unreachable. */
#define ZN_PLAN_ATTEMPTS_TREE 3

/* Asks the daemon for the Zygisk Next libraries targeting this process and loads
   them. For the zygote itself, where the process name comes from
   /proc/self/exe.

   The daemon is the only source of the plan: there is no fallback that reads
   /data/adb/modules directly: a process outside the zygote's domain could not
   read that tree anyway, and a loader that reads it on its own can disagree
   with the daemon about what is installed.

   `connect_retry` is the number of extra attempts after the first, spaced
   `connect_delay_us` apart. */
void zn_load_all_modules(uint8_t connect_retry, uint32_t connect_delay_us);

/* The same scan for a forked child about to specialize: only the modules naming
   `process_name` are loaded, and libraries inherited from the zygote are
   skipped. The daemon is long up by then, so one attempt is enough. */
void zn_load_modules_for_process(const char *process_name);

/* Whether this process is one the loader was injected into, rather than one it
   was loaded into on an application's behalf. A target is still having modules
   mapped into it while they load, so what is read about it has to be current;
   an application's table is already complete. See zn_api.c. */
extern bool zn_injected_target;

/* Opens a fresh connection to the companion of the module behind `handle`, the
   self handle from onModuleLoaded. The socket, or -1 when there is no reachable
   companion. */
int zn_companion_connect(void *handle);

/* How many Zygisk Next libraries this process holds. Zero means its maps carry
   none of ours; a count inherited from the zygote comes with the libraries it
   was raised for. */
size_t zn_loaded_library_count(void);

#endif /* ZN_LOADER_H */
