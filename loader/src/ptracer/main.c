#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <limits.h>

#include <sys/ptrace.h>
#include <signal.h>

#include "daemon.h"
#include "monitor.h"

/* INFO: The monitor's own entry: it never returns like the CLI subcommands do,
         it takes over the process. stdout is the module script's pipe, drained
         into the root manager's log; the monitor is long-lived and its findings
         go to logd, so the pipe side channel is cut at startup instead of
         turning every status line into a wakeup of the log drainer. The CLI
         subcommands below keep real stdout. */
static int run_monitor(void) {
  if (freopen("/dev/null", "w", stdout) == NULL) {
    /* INFO: Keep the inherited stdout; logd output is unaffected. */
  }

  init_monitor();

  return 0;
}

static int run_trace(int argc, char **argv) {
  bool do_restart = false;

  for (int i = 3; i < argc; i++) {
    if (strcmp(argv[i], "--restart") == 0) do_restart = true;
  }

  /* INFO: Validate before any side effect: a bogus pid would otherwise reach
            the kill() below as 0, which signals the whole process group, and
            --restart would have already killed the live zygote before the bad
            argument was noticed - leaving the system without a tracer for the
            one the init process forks in its place. */
  char *pid_end = NULL;
  long pid = strtol(argv[2], &pid_end, 0);
  if (pid <= 0 || pid > INT_MAX || pid_end == argv[2] || *pid_end != '\0') {
    printf("[VexZygisk]: Invalid pid \"%s\"\n", argv[2]);

    return 1;
  }

  if (do_restart) rezygiskd_zygote_restart();

  /* EXITKILL only where the caller would kill the target on failure anyway. */
  if (!trace_zygote((int)pid, do_restart)) {
    /* A restart traces a zygote the monitor is replacing, so a failure leaves
       nothing worth keeping and it is killed. The first trace of a boot is only
       detached and resumed: killing it there would leave the system with no
       process to fork applications from. */
    if (do_restart) {
      kill((pid_t)pid, SIGKILL);
    } else {
      ptrace(PTRACE_DETACH, (pid_t)pid, 0, SIGCONT);
      kill((pid_t)pid, SIGCONT);
    }

    return 1;
  }

  return 0;
}

static int run_ctl(const char *subcommand, const char *program) {
  enum rezygiskd_command command;

  if (strcmp(subcommand, "start") == 0) command = START;
  else if (strcmp(subcommand, "stop") == 0) command = STOP;
  else if (strcmp(subcommand, "exit") == 0) command = EXIT;
  else {
    printf("[VexZygisk]: Usage: %s ctl <start|stop|exit>\n", program);

    return 1;
  }

  if (send_control_command(command) == -1) {
    printf("[VexZygisk]: Failed to send the command, is the daemon running?\n");

    return 1;
  }

  printf("[VexZygisk]: command sent\n");

  return 0;
}

static int run_info(void) {
  struct rezygisk_info info = { 0 };
  rezygiskd_get_info(&info);

  if (!info.running) {
    printf("[VexZygisk]: The daemon is not running\n");

    return 1;
  }

  printf("Daemon process PID: %d\n", info.pid);

  /* INFO: The switch is over the one value this flavour's daemon can report,
            which keeps a flavour that reports something else a compile error in
            its own terms rather than a line that silently says nothing. */
#ifdef ROOT_IMPL_APATCH
  switch (info.root_impl) {
    case ROOT_APATCH: {
      printf("Root implementation: APatch\n");

      break;
    }
  }
#else
  switch (info.root_impl) {
    case ROOT_KERNELSU: {
      printf("Root implementation: KernelSU\n");

      break;
    }
  }
#endif

  if (info.modules.modules_count != 0) {
    printf("Modules: %zu\n", info.modules.modules_count);

    for (size_t i = 0; i < info.modules.modules_count; i++) {
      printf(" - %s\n", info.modules.modules[i]);
    }
  } else {
    printf("Modules: N/A\n");
  }

  free_rezygisk_info(&info);

  return 0;
}

static void print_usage(void) {
  printf(
    "Available commands:\n"
    " - monitor\n"
    " - trace <pid> [--restart]\n"
    " - ctl <start|stop|exit>\n"
    " - version: Shows the version of VexZygisk.\n"
    " - info: Shows information about the created daemon/injection.\n"
    "\n"
    "<...>: Obligatory\n"
    "[...]: Optional\n");
}

int main(int argc, char **argv) {
  printf("The VexZygisk Tracer %s\n\n", ZKSU_VERSION);

  if (argc >= 2 && strcmp(argv[1], "monitor") == 0) return run_monitor();

  if (argc >= 3 && strcmp(argv[1], "trace") == 0) return run_trace(argc, argv);

  if (argc >= 3 && strcmp(argv[1], "ctl") == 0) return run_ctl(argv[2], argv[0]);

  if (argc >= 2 && strcmp(argv[1], "version") == 0) {
    printf("[VexZygisk]: %s\n", ZKSU_VERSION);

    return 0;
  }

  if (argc >= 2 && strcmp(argv[1], "info") == 0) return run_info();

  print_usage();

  return 1;
}
