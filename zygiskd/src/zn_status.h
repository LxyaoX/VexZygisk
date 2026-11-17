#ifndef ZN_STATUS_H
#define ZN_STATUS_H

#include <stddef.h>

/* What the last plans came to, written where the module card can show it.

   An empty plan looks the same from the loader whichever thing went wrong - no
   module held a list, no row named this process, the library would not open -
   and the daemon is the only side that knows which. A release build compiles
   every log line out, so the answer goes to a file and the monitor reads it back
   onto the card.

   Only requests from a process that hosts the runtime are recorded: one the
   zygote-class names resolve to, or the process that reported a runtime image. An
   application asking for its own plan says nothing about whether the path works.

   `example_target` is the first row that did not name this process, kept for the
   case where none did - it is what a reader compares against the reported name,
   and that comparison is the whole diagnosis. */

void zn_status_record(const char *process_name, size_t dirs_walked,
                      size_t lists_valid, size_t rows_examined,
                      size_t rows_matched, const char *example_target);

#endif /* ZN_STATUS_H */
