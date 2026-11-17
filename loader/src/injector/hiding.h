#ifndef HIDING_H
#define HIDING_H

#include <stdbool.h>

/* The one trace the mount revert cannot reach: a library still mapped into a
   hidden process names its own file in /proc/self/maps - the injector itself,
   every module library the loader abandons rather than unloads, and every Zygisk
   Next library the system linker holds. Per process, and final only once the
   modules have run.

   The other half is bionic's static mount line, which the zygote hands down to
   every application; that one lives in unmount.c next to the revert, see
   refresh_mount_line(). */

bool hide_module_maps(void);

/* Whether hide_module_maps() has already run in this process. The specialize
   path hides once after the modules run, the teardown hides again as its last
   step, and finding out the second time costs a fork and a walk of the whole
   table. The teardown asks first; a process the specialize path never reached
   still gets its one pass. */
bool module_maps_hidden(void);

#endif /* HIDING_H */
