#ifndef ZN_COMPANION_PROTOCOL_H
#define ZN_COMPANION_PROTOCOL_H

/* The wire contract of the Zygisk Next companion socket, shared by the loader
   side that serves it (injector/zn_loader.c) and the daemon side that hosts it
   as `zygiskd zn-companion` (zygiskd/src/zn_companion.c). Both halves used to
   carry a copy, and a command byte edited on one side alone only showed up as a
   companion that never connects. */

#include <stdint.h>

#include <sys/socket.h>

/* The framing and the control-message buffer the descriptor handshake needs. */
#include "socket_protocol.h"

/* Command byte the module sends when it calls connectCompanion. */
#define ZN_COMPANION_CMD_CONNECT ((uint8_t)1)

/* The byte the companion writes as it takes the connection over, and the loader
   reads before handing the socket to the module. Without it the two race: the
   module can reach its end before the companion accepted it, and the loader
   hands out a socket it has no evidence the companion holds. Both companion
   halves send it from here, so a forked and a daemon-hosted companion stay
   indistinguishable to the module. */
#define ZN_COMPANION_ACK ((uint8_t)1)

/* How long the loader waits for that byte. It covers a companion that is already
   running, so the wait is short - but bounded: a companion from an older build
   never acknowledges, and blocking would turn a version skew into a hung
   connectCompanion instead of a socket that still works. */
#define ZN_COMPANION_ACK_TIMEOUT_MS 1000

#endif /* ZN_COMPANION_PROTOCOL_H */
