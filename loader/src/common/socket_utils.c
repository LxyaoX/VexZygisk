#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <sys/socket.h>

#include "logging.h"

#include "socket_utils.h"

char *read_string(int fd) {
  uint32_t str_len = 0;
  ssize_t read_bytes = read_loop(fd, &str_len, sizeof(str_len));
  if (read_bytes != (ssize_t)sizeof(str_len)) {
    LOGE("Failed to read string length: Not all bytes were read (%zd != %zu).\n", read_bytes, sizeof(str_len));

    return NULL;
  }

  /* A length makes sense up to a path's worth of bytes; beyond it the stream is
     desynchronised and the allocation would grow without bound. */
  if (str_len > (1u << 20)) {
    LOGE("Failed to read string: Length %u is out of bounds.\n", str_len);

    return NULL;
  }

  char *buf = malloc((size_t)str_len + 1);
  if (buf == NULL) {
    PLOGE("allocate memory for string");

    return NULL;
  }

  read_bytes = read_loop(fd, buf, str_len);
  if (read_bytes != (ssize_t)str_len) {
    LOGE("Failed to read string: Promised bytes doesn't exist (%zd != %u).\n", read_bytes, str_len);

    free(buf);

    return NULL;
  }

  buf[str_len] = '\0';

  return buf;
}
