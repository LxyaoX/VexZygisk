#ifndef ZN_API_H
#define ZN_API_H

#include "zygisk_next_api.h"

/* The oldest Zygisk Next module contract this fork serves. Every entry of the
   table is real, which only holds while what is served is the contract as it
   stands: an older module describes a table whose fields have moved, and handing
   it one it would read at the wrong offsets is worse than telling it no. Zygisk
   Next's versions 3 and 4 are the two this serves. */
#define ZN_MODULE_API_MIN 3

/* The table handed to every Zygisk Next module this loader loads. */
const struct ZygiskNextAPI *zn_get_api(void);

#endif /* ZN_API_H */
