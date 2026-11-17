#ifndef ZN_LSPLT_H
#define ZN_LSPLT_H

/* The C bridge to LSPlt (injector/zn_lsplt_shim.cpp), the hooking engine the
   LSPosed ecosystem builds its modules against. Both the Zygisk Next pltHook
   entry and the HyperOS runtime's own hooks in the spawner go through it, so both
   entry points live here. The shim stays C++ because LSPlt is, and its exception
   barrier keeps a throw out of the injector's C frames.

   All of these return 0 on success and -1 on failure - an inverted bool at the
   boundary, so no caller has to know what LSPlt speaks. */

#include <sys/types.h>

int zn_lsplt_register_hook(dev_t dev, ino_t inode, const char *symbol, void *hook, void **backup);
int zn_lsplt_commit_hook(void);

/* The same commit against the map snapshot LSPlt already took in this process.

   The snapshot comes from the first commit that runs, the spawner's, and every
   application inherits it with the rest of the memory - so a forked side commits
   against it instead of reading /proc/self/maps again. -1 when no snapshot exists
   yet, exactly as a fresh scan would fail. */
int zn_lsplt_commit_hook_cached(void);

#endif /* ZN_LSPLT_H */
