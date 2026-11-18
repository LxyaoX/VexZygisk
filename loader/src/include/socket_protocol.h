#ifndef REZYGISK_SOCKET_PROTOCOL_H
#define REZYGISK_SOCKET_PROTOCOL_H

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

/* The wire protocol: the loader and the daemon have to agree byte for byte, so
   it exists once, here. Static inline because the two are separate programs and
   a shared .c would have to be linked into both.

   Nothing here logs. The caller knows which exchange failed and names it; a
   helper that logs too says the same thing twice. */

/* The kernel may copy a struct cmsghdr into the control buffer, so it has to be
   aligned as one. Both ends allocate this and the sizes must match. */
union cmsg_buffer {
  struct cmsghdr header;
  char control[CMSG_SPACE(sizeof(int))];
};

/* EAGAIN is never retried in either loop: every socket on this path carries
   SO_SNDTIMEO/SO_RCVTIMEO (rezygiskd_connect sets it), so it means the deadline
   expired, and retrying would turn the timeout into decoration. EINTR is
   retried. The monitor's non-blocking datagram socket reaches read_loop too,
   but only after an edge-triggered EPOLLIN: it has the whole datagram or a
   permanent error. */
static inline ssize_t write_loop(int fd, const void *buf, size_t count) {
  const char *data = (const char *)buf;
  size_t written = 0;

  while (written < count) {
    ssize_t ret = write(fd, data + written, count - written);
    if (ret == -1) {
      if (errno != EINTR) return -1;

      continue;
    }

    if (ret == 0) return (ssize_t)written;

    written += (size_t)ret;
  }

  return (ssize_t)written;
}

static inline ssize_t read_loop(int fd, void *buf, size_t count) {
  char *data = (char *)buf;
  size_t read_bytes = 0;

  while (read_bytes < count) {
    ssize_t ret = read(fd, data + read_bytes, count - read_bytes);
    if (ret == -1) {
      if (errno != EINTR) return -1;

      continue;
    }

    if (ret == 0) return (ssize_t)read_bytes;

    read_bytes += (size_t)ret;
  }

  return (ssize_t)read_bytes;
}

/* One descriptor with the single data byte the peer writes alongside it. */
static inline ssize_t write_fd(int fd, int sendfd) {
  union cmsg_buffer cmsgbuf;
  char buf[1] = { 0 };

  struct iovec iov = {
    .iov_base = buf,
    .iov_len = sizeof(buf)
  };

  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsgbuf.control,
    .msg_controllen = sizeof(cmsgbuf.control)
  };

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;

  memcpy(CMSG_DATA(cmsg), &sendfd, sizeof(int));

  /* MSG_NOSIGNAL: a peer that closed its end would turn this into SIGPIPE, and
     several callers run inside app processes that do not ignore it. */
  return sendmsg(fd, &msg, MSG_NOSIGNAL);
}

static inline int read_fd(int fd) {
  union cmsg_buffer cmsgbuf;
  char buf[1] = { 0 };

  struct iovec iov = {
    .iov_base = buf,
    .iov_len = sizeof(buf)
  };

  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsgbuf.control,
    .msg_controllen = sizeof(cmsgbuf.control)
  };

  ssize_t ret;
  do {
    ret = recvmsg(fd, &msg, MSG_WAITALL);
  } while (ret == -1 && errno == EINTR);

  if (ret == -1) return -1;

  /* Truncated control data: the kernel closes a descriptor it could not
     deliver, so walking a half-written buffer is never the right answer. */
  if (msg.msg_flags & MSG_CTRUNC) return -1;

  struct cmsghdr *cmsg;
  int sendfd = -1;

  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len < CMSG_LEN(sizeof(int))) continue;

    memcpy(&sendfd, CMSG_DATA(cmsg), sizeof(int));

    break;
  }

  if (sendfd == -1) return -1;

  return sendfd;
}

static inline ssize_t write_uint8_t(int fd, uint8_t val) {
  return write_loop(fd, &val, sizeof(val));
}

static inline ssize_t read_uint8_t(int fd, uint8_t *val) {
  return read_loop(fd, val, sizeof(*val));
}

static inline ssize_t write_uint32_t(int fd, uint32_t val) {
  return write_loop(fd, &val, sizeof(val));
}

static inline ssize_t read_uint32_t(int fd, uint32_t *val) {
  return read_loop(fd, val, sizeof(*val));
}

/* Counts ride the wire as uint32_t: a size_t would make the protocol's shape
   depend on the ABI of whichever side compiled it. Everything that crosses here
   is a module count or an index into them, so the narrowing bound is never met
   in practice. The comparison is 64-bit wide so a 32-bit size_t does not make
   it a tautology. */
static inline ssize_t write_size_t(int fd, size_t val) {
  if ((uint64_t)val > (uint64_t)UINT32_MAX) return -1;

  uint32_t wire = (uint32_t)val;

  return write_loop(fd, &wire, sizeof(wire));
}

static inline ssize_t read_size_t(int fd, size_t *val) {
  uint32_t wire = 0;
  ssize_t read_bytes = read_loop(fd, &wire, sizeof(wire));

  if (read_bytes == (ssize_t)sizeof(wire) && val != NULL) *val = wire;

  return read_bytes;
}

/* A length-prefixed string: the byte count that follows, no terminator, fixed
   uint32_t on the wire. Only the framing is shared - the loader allocates and
   the daemon fills a caller's buffer. A NULL string is written as empty, which
   keeps the framing aligned for the optional path one call site passes. */
static inline ssize_t write_string(int fd, const char *str) {
  size_t str_len = str != NULL ? strlen(str) : 0;

  if (str_len > UINT32_MAX) return -1;

  uint32_t wire_len = (uint32_t)str_len;

  if (write_loop(fd, &wire_len, sizeof(wire_len)) != (ssize_t)sizeof(wire_len)) return -1;

  if (str_len == 0) return 0;

  return write_loop(fd, str, str_len) == (ssize_t)str_len ? (ssize_t)str_len : -1;
}

#endif /* REZYGISK_SOCKET_PROTOCOL_H */
