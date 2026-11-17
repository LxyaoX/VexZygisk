#ifndef UNMOUNT_H
#define UNMOUNT_H

#include <stdbool.h>
#include <stdint.h>

/* Revert-only is how denylisted processes are hidden by default: the process gets
   a private copy of the mount tree and the root traces are stripped from it in
   place. Unlike a namespace switch this leaves everyone else's mounts alone, so
   metamodule overlays stay visible and each app ends up with a namespace of its
   own. A metamodule's mounts are indistinguishable from a root trace, which is
   why this only ever runs on the processes being hidden. */

/* True unless a disable-revert marker opts the device out. */
bool revert_mode_enabled(void);

/* Strips the root traces from the mount namespace this process is in; true when
   nothing is left to hide. Run right after a denylisted process unshared its own
   copy. False means the caller should switch namespaces instead. */
bool revert_root_traces_here(void);

/* Re-parses this process's own mount table, which is what replaces the copy
   bionic keeps in a static buffer - taken while the module mounts were still
   there, so a cleaned process can still read the mounts out of its own libc.
   Call it under the same flag as the revert, once the tree is the cleaned one. */
bool refresh_mount_line(void);

#endif /* UNMOUNT_H */
