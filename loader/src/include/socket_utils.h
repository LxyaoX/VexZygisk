#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>

/* The framing and the scalar readers live in socket_protocol.h, shared with the
   daemon. What is left here is this side's read_string, which allocates where
   the daemon's fills a caller's buffer. */
#include "socket_protocol.h"

char *read_string(int fd);

#endif /* SOCKET_UTILS_H */
