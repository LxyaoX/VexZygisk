#ifndef ZN_HYOS_H
#define ZN_HYOS_H

/* INFO: The HyperOS ("HYOS") runtime contract, as Zygisk Next defines it and
         YukiZygisk implements it.

         On HyperOS, applications are not forked by a zygote but by
         /system_ext/bin/hyos_spawner, which runs them on a Rust runtime of its
         own. There is no ART specialization to hook there - the hooks that
         announce one are what crashed the spawner and left every application
         unable to start - so the runtime carries the module contract instead: a
         module loaded into the spawner calls getRuntime(), gets this table, and
         registers an onAppSpecialized callback. The runtime then installs its
         own hooks in the spawner, and every application forked from it reaches
         the callback with its process name, package name and SELinux context.

         The shape of that is fixed by the ABI header (zygisk_next_api.h); this
         file is the rest of the contract: when the runtime exists, what a
         module has to look like to register, how the hooks are installed and
         rolled back, and how a specialization reaches the modules. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "misc.h"
#include "zn_spawner.h"
#include "zygisk_next_api.h"

/* INFO: The layout of the contract, pinned where every table is built.

         A module is compiled against its own copy of zygisk_next_api.h, and the
         compiler building it has never seen ours. Nothing about a field that
         moved fails to build on either side: the module links, the call goes
         through, and the function pointer it lands on belongs to some other
         entry. The reference implementations assert the same facts, and so does
         this - for the API table field by field, and for every structure a
         module hands over or receives.

         These live here rather than in zygisk_next_api.h itself because the
         daemon compiles that header as C99 with -Wpedantic -Werror, where
         _Static_assert is not part of the language. Every translation unit that
         builds or reads one of these tables includes this file. */

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

/* INFO: How much of a specialization string is copied before it is handed to
         the modules. The contract promises strings that live for the length of
         the callback, and the buffers they point at are these; a value that
         does not fit is refused rather than truncated, because half a package
         name is a wrong package name that no module can tell from a real one. */
#define ZN_HYOS_VALUE_MAX 512

/* INFO: Opens a control session to the daemon from the process that has the
         privilege to do so - the spawner, before it forks - and returns the
         descriptor the forked child will report over, or -1 when there is no
         session to be had. The descriptor is inherited by the child, which is
         the whole point: the child is sandboxed by then and cannot open one of
         its own. */
typedef int (*zn_hyos_open_session_fn)(void);

/* INFO: Records that `module_id` specialized the process the callback runs in.
         Returning false is not an error the runtime acts on - the callback
         contract has been met either way - it is only what can be said about
         the record. */
typedef bool (*zn_hyos_report_fn)(const char *module_id);

/* INFO: Looks for the runtime in this process and, when it is there, opens the
         window in which modules may register. Returns false when this process
         does not host it, which is the answer for everything that is not the
         spawner and its tree.

         Called once, from entry(), before any module is loaded: a module
         registers while it is being loaded, so the window has to be open
         first. */
bool zn_hyos_initialize(zn_hyos_open_session_fn open_session, zn_hyos_report_fn report);

/* INFO: The runtime table for the modules of this process, or NULL when there
         is no runtime here. This is what getRuntime() answers with, and this
         fork answers "no runtime" only for a process the runtime was never
         found in. */
const struct ZygiskNextRuntime *zn_hyos_runtime(void);

/* INFO: Closes the registration window and installs the runtime's hooks in the
         spawner. Returns false when they could not be installed, in which case
         none of them is left behind and no callback will ever fire.

         Called after the modules have been loaded, because that is what the
         hooks are for: a runtime nobody registered against has nothing to
         announce, and installing them anyway would only add a fork hook to a
         boot that has no module to tell about it. */
bool zn_hyos_install_hooks(void);

/* INFO: The control session this process reports over, or -1. In the spawner it
         is -1 until a fork hands the child its own; in an application it is
         what the fork opened on its behalf. */
int zn_hyos_child_session(void);

/* INFO: Whether this process was forked by the spawner - the application side
         of the runtime, whether or not its session came up.

         It is asked where the answer changes what is right rather than what is
         possible: an application inherits the spawner's memory, the map
         snapshot LSPlt took when it installed the runtime's own hooks included,
         so it can commit against that snapshot instead of reading
         /proc/self/maps again. See zn_lsplt.h. */
bool zn_hyos_in_child(void);
const char *zn_hyos_image_path(void);

/* INFO: The path the runtime image is mapped from, or an empty string when this
         process does not host the runtime.

         It is the executable on the builds where the spawner is its own file,
         and it is the image mapped into an ART host on the ones where it is not
         - which is the difference the module plan needs: a manifest target that
         spells this path is naming this process whichever file it exec'd, and
         /proc/self/exe alone cannot answer that. */

/* INFO: Tells the runtime which module is being loaded, so a registration made
         from inside that module's onModuleLoaded can be attributed to it. The
         string is not copied: the caller keeps it alive for the life of the
         process, as the loader's module table does. */
void zn_hyos_begin_module_registration(const char *module_id);
void zn_hyos_end_module_registration(void);

/* INFO: Whether a module may register at all. The contract names exactly one
         version of the HyperOS runtime API - the one in zygisk_next_api.h - and
         a module built against anything else describes a structure this
         runtime would have to guess at, so it is refused rather than served.
         YukiZygisk draws the line in the same place. */
static inline bool zn_hyos_module_api_matches(int target_api_version) {
  return target_api_version == ZYGISK_NEXT_HYOS_API_VERSION;
}

#endif /* ZN_HYOS_H */
