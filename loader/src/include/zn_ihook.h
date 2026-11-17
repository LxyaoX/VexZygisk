#ifndef ZN_IHOOK_H
#define ZN_IHOOK_H

/* The C bridge to the inline hook engine behind the Zygisk Next inlineHook entry
   (injector/ihook_shim.cpp, over src/external/ihook/). The engine is
   YukiZygisk's, taken whole: the same relocating arm64 patcher, the same
   instruction-cache synchronization. It is C++ and this injector is C, so the
   boundary is a pair of calls and a hook is named by the address it was placed
   on, which is what the contract keys on.

   Both answer false when the engine refuses - a process with more than one
   thread, an address inside another hook's window, an address the relocator
   cannot rewrite - and the shim logs why. */

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Places the hook and hands back the address the original can be called through
   as `*original` (untouched when the caller passed NULL). */
bool zn_ihook_install(void *target, void *replacement, void **original);

/* Removes the hook on `target` and reclaims its trampoline, restoring the bytes
   rather than discarding the page. */
bool zn_ihook_uninstall(void *target);

#ifdef __cplusplus
}
#endif

#endif /* ZN_IHOOK_H */
