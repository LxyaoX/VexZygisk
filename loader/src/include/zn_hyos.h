#ifndef ZN_HYOS_H
#define ZN_HYOS_H

/* The HyperOS runtime contract, as Zygisk Next defines it and YukiZygisk
   implements it.

   HyperOS does not fork applications from a zygote but from
   /system_ext/bin/hyos_spawner, on a Rust runtime of its own. There is no ART
   specialization to hook there - the hooks that announce one crash the spawner
   - so the runtime carries the module contract instead: a module loaded into
   the spawner calls getRuntime(), registers an onAppSpecialized callback, and
   the runtime's own hooks reach it for every application the spawner forks.

   The ABI shape is zygisk_next_api.h; this file is the rest: when the runtime
   exists, what a module has to look like, how the hooks are installed and
   rolled back, and how a specialization reaches the modules. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "misc.h"
#include "zn_spawner.h"
#include "zygisk_next_api.h"

/* The contract's layout, pinned where every table is built. A module is
   compiled against its own copy of zygisk_next_api.h, so a field that moved
   fails to build on neither side - the call goes through and lands on some
   other entry. These live here rather than in zygisk_next_api.h because the
   daemon compiles that header as C99, where _Static_assert does not exist. */

_Static_assert(sizeof(struct ZygiskNextAPI) == 10 * sizeof(void *),
               "the Zygisk Next API table is ten pointers");
_Static_assert(offsetof(struct ZygiskNextAPI, pltHook) == 0 * sizeof(void *),
               "pltHook is the first entry of the Zygisk Next API table");
_Static_assert(offsetof(struct ZygiskNextAPI, inlineHook) == 1 * sizeof(void *),
               "inlineHook is the second entry of the Zygisk Next API table");
_Static_assert(offsetof(struct ZygiskNextAPI, inlineUnhook) == 2 * sizeof(void *),
               "inlineUnhook is the third entry of the Zygisk Next API table");
_Static_assert(offsetof(struct ZygiskNextAPI, newSymbolResolver) == 3 * sizeof(void *),
               "newSymbolResolver is the fourth entry of the Zygisk Next API table");
_Static_assert(offsetof(struct ZygiskNextAPI, freeSymbolResolver) == 4 * sizeof(void *),
               "freeSymbolResolver is the fifth entry of the Zygisk Next API table");
_Static_assert(offsetof(struct ZygiskNextAPI, getBaseAddress) == 5 * sizeof(void *),
               "getBaseAddress is the sixth entry of the Zygisk Next API table");
_Static_assert(offsetof(struct ZygiskNextAPI, symbolLookup) == 6 * sizeof(void *),
               "symbolLookup is the seventh entry of the Zygisk Next API table");
_Static_assert(offsetof(struct ZygiskNextAPI, forEachSymbols) == 7 * sizeof(void *),
               "forEachSymbols is the eighth entry of the Zygisk Next API table");
_Static_assert(offsetof(struct ZygiskNextAPI, connectCompanion) == 8 * sizeof(void *),
               "connectCompanion is the ninth entry of the Zygisk Next API table");
_Static_assert(offsetof(struct ZygiskNextAPI, getRuntime) == 9 * sizeof(void *),
               "getRuntime is the last entry of the Zygisk Next API table");

_Static_assert(sizeof(struct ZygiskNextModule) == 2 * sizeof(void *),
               "a Zygisk Next module entry is a version and a callback");
_Static_assert(offsetof(struct ZygiskNextModule, onModuleLoaded) == sizeof(void *),
               "onModuleLoaded follows the version of a Zygisk Next module entry");

_Static_assert(sizeof(struct ZygiskNextRuntime) ==
                   ((2 * sizeof(int) + _Alignof(void *) - 1) & ~(_Alignof(void *) - 1)) + sizeof(void *),
               "the runtime table is two ints and one pointer");
_Static_assert(offsetof(struct ZygiskNextRuntime, registerModule) ==
                   ((2 * sizeof(int) + _Alignof(void *) - 1) & ~(_Alignof(void *) - 1)),
               "registerModule sits after the two ints of the runtime table");

_Static_assert(sizeof(struct ZnHyosAppSpecializeArgs) == 3 * sizeof(void *),
               "the specialize arguments are three strings");
_Static_assert(sizeof(struct ZygiskNextHyosModule) == 2 * sizeof(void *),
               "a HyperOS module entry is a version and a callback");
_Static_assert(offsetof(struct ZygiskNextHyosModule, onAppSpecialized) ==
                   ((sizeof(int) + _Alignof(void *) - 1) & ~(_Alignof(void *) - 1)),
               "onAppSpecialized follows the version of a HyperOS module entry");
_Static_assert(sizeof(struct ZygiskNextHyosModule) ==
                   offsetof(struct ZygiskNextHyosModule, onAppSpecialized) + sizeof(void *),
               "a HyperOS module entry ends with its callback");

_Static_assert(sizeof(struct ZygiskNextCompanionModule) == 3 * sizeof(void *),
               "a companion entry is a version and two callbacks");
_Static_assert(offsetof(struct ZygiskNextCompanionModule, onModuleConnected) == 2 * sizeof(void *),
               "onModuleConnected is the last callback of a companion entry");

/* How much of a specialization string is copied before it reaches the modules.
   A value that does not fit is refused, not truncated: half a package name is
   a wrong package name no module can tell from a real one. */
#define ZN_HYOS_VALUE_MAX 512

/* Opens a control session to the daemon from the process that has the
   privilege - the spawner, before it forks - and returns the descriptor the
   child will report over. The child inherits it; by the time it runs it is
   sandboxed and cannot open one of its own. */
typedef int (*zn_hyos_open_session_fn)(void);

/* Records that `module_id` specialized the process the callback runs in. False
   is not an error the runtime acts on, only what can be said about the record. */
typedef bool (*zn_hyos_report_fn)(const char *module_id);

/* Looks for the runtime in this process and, when it is there, opens the window
   in which modules may register. Called once from entry(), before any module is
   loaded: a module registers while it is being loaded. False for every process
   that does not host the runtime. */
bool zn_hyos_initialize(zn_hyos_open_session_fn open_session, zn_hyos_report_fn report);

/* The runtime table for the modules of this process, or NULL when there is no
   runtime here. This is what getRuntime() answers with. */
const struct ZygiskNextRuntime *zn_hyos_runtime(void);

/* Closes the registration window and installs the runtime's hooks in the
   spawner. False when they could not be installed, in which case none is left
   behind and no callback will ever fire. Called after the modules have loaded:
   a runtime nobody registered against has nothing to announce. */
bool zn_hyos_install_hooks(void);

/* The control session this process reports over, or -1. In the spawner it is
   -1 until a fork hands the child its own; in an application it is what the
   fork opened on its behalf. */
int zn_hyos_child_session(void);

/* Whether this process was forked by the spawner, whether or not its session
   came up. It is asked where the answer changes what is right rather than what
   is possible: such a process inherited LSPlt's map snapshot and can commit
   against it instead of reading /proc/self/maps again (see zn_lsplt.h). */
bool zn_hyos_in_child(void);

/* The path the runtime image is mapped from, or "" when this process does not
   host the runtime. It is the executable where the spawner is its own file, and
   the mapped-in image where it is not - which is what a manifest target needs:
   /proc/self/exe alone cannot name the second case. */
const char *zn_hyos_image_path(void);

/* Tells the runtime which module is being loaded, so a registration made from
   inside its onModuleLoaded can be attributed to it. The string is not copied:
   the caller keeps it alive for the life of the process. */
void zn_hyos_begin_module_registration(const char *module_id);
void zn_hyos_end_module_registration(void);

/* The contract names exactly one HyperOS runtime API version; a module built
   against anything else describes a structure this runtime would have to guess
   at. YukiZygisk draws the line in the same place. */
static inline bool zn_hyos_module_api_matches(int target_api_version) {
  return target_api_version == ZYGISK_NEXT_HYOS_API_VERSION;
}

#endif /* ZN_HYOS_H */
