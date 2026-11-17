#ifndef MONITOR_STATUS_H
#define MONITOR_STATUS_H

#include <stdbool.h>

#include "monitor.h"

/* The module card and state.json, in their own file. Neither is part of tracing,
   and both exist because a release build compiles every log line out: the card is
   the only place this monitor still says anything once it ships.

   The monitor fills in a struct monitor_status_view and calls these; nothing here
   holds state beyond the buffers the text is assembled in. */

/* Captures the pristine description this run is written in front of, once,
   before the first write. False when module.prop cannot be read at all, which is
   a broken installation rather than a card that will not refresh. */
bool monitor_status_prepare(void);

/* Writes the card, and state.json with it. `message` replaces the generated
   status line and skips the state file: those callers carry a transient note
   about what just happened, not a status. */
bool monitor_status_update(const struct monitor_status_view *view, const char *message);

#endif /* MONITOR_STATUS_H */
