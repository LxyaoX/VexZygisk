#ifndef MONITOR_H
#define MONITOR_H

#include <stdbool.h>
#include <stdint.h>

#include <sys/types.h>

/* The ABI this monitor injects, as the card and the tracer command line spell
   it. There is one monitor binary and it is the 64-bit one. */
#define MONITOR_ABI "64"

/* One module as the daemon reported it. */
struct daemon_module {
  char *name;
};

/* Where the monitor is in its own life; the card words each one differently. */
enum ptracer_tracing_state {
  TRACING,
  STOPPING,
  STOPPED,
  EXITING
};

/* The monitor's state as the card draws it, filled in at the one place the
   monitor hands it over. Every field is read from the monitor's own variables at
   that moment, so there is no second copy of "is the daemon running". */
struct monitor_status_view {
  enum ptracer_tracing_state state;

  /* Why tracing stopped, NULL while it has not. */
  const char *stop_reason;

  const char *root_impl;
  const char *daemon_error;

  const struct daemon_module *modules;
  uint32_t modules_len;

  bool supported;
  bool zygote_injected;
  bool daemon_running;
};

void init_monitor();

/* `exit_kill` says whether a tracer death may take the target with it
   (PTRACE_O_EXITKILL): yes for a zygote the monitor restarts anyway. */
bool trace_zygote(int pid, bool exit_kill);

pid_t monitor_parent_of(int pid);

enum rezygiskd_command {
  START = 1,
  STOP = 2,
  EXIT = 3,

  /* Sent from the daemon. The gaps are retired 32-bit counterparts: these are
     wire values shared with the daemon, so they keep their numbers. */
  ZYGOTE64_INJECTED = 4,
  DAEMON64_SET_INFO = 6,
  DAEMON64_SET_ERROR_INFO = 8,

  /* One module record of the list DAEMON64_SET_INFO announced. Its own datagram,
     because a datagram is the only unit this socket delivers whole: each record
     is self-describing from its first byte, so a lost or stray one can never be
     read as the middle of another. */
  DAEMON64_MODULE_ENTRY = 9
};

int send_control_command(enum rezygiskd_command cmd);

#endif /* MONITOR_H */
