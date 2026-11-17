#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>

#include <unistd.h>
#include <sys/ptrace.h>

#include <link.h>

#include "misc.h"

#ifndef LOG_TAG
  #define LOG_TAG "zygisk-ptrace"
#endif

#include "logging.h"

/* aarch64 only: the tracer is built for arm64-v8a and traces the bitness it runs
   as, so there is no second register file to pick between. */
#define REG_SP sp
#define REG_IP pc
#define REG_RET regs[0]
#define REG_SYSNR regs[8]

ssize_t write_proc(int pid, uintptr_t remote_addr, const void *buf, size_t len);

ssize_t read_proc(int pid, uintptr_t remote_addr, void *buf, size_t len);

bool get_regs(int pid, struct user_regs_struct *regs);

bool set_regs(int pid, struct user_regs_struct *regs);

const char *position_after(const char *str, const char needle);

void *find_module_return_addr(struct maps_info *map, const char *suffix);

void *find_func_addr(struct maps_info *local_info, struct maps_info *remote_info, const char *module, const char *func);

void align_stack(struct user_regs_struct *regs, long preserve);

uintptr_t remote_call(int pid, struct user_regs_struct *regs, uintptr_t func_addr, uintptr_t return_addr, long *args, size_t args_size);

int fork_dont_care();

bool wait_linker_ready(int pid, uintptr_t *out_libc_init_resolved, uintptr_t *out_libc_init_got_slot);

bool ptrace_poke_uintptr(pid_t pid, uintptr_t addr, uintptr_t value);

bool wait_for_ptrace_syscall_stop(int pid, int *status);

/* False when the tracee's registers could not be rewritten; the caller must not
   continue the trapped syscall in that case. */
bool tracee_skip_syscall(int pid);

void wait_for_trace(int pid, int *status, int flags);

void parse_status(int status, char *buf, size_t len);

#define WPTEVENT(x) (x >> 16)

#define CASE_CONST_RETURN(x) case x: return #x;

static inline const char *parse_ptrace_event(int status) {
  status = status >> 16;

  switch (status) {
    CASE_CONST_RETURN(PTRACE_EVENT_FORK)
    CASE_CONST_RETURN(PTRACE_EVENT_VFORK)
    CASE_CONST_RETURN(PTRACE_EVENT_CLONE)
    CASE_CONST_RETURN(PTRACE_EVENT_EXEC)
    CASE_CONST_RETURN(PTRACE_EVENT_VFORK_DONE)
    CASE_CONST_RETURN(PTRACE_EVENT_EXIT)
    CASE_CONST_RETURN(PTRACE_EVENT_SECCOMP)
    CASE_CONST_RETURN(PTRACE_EVENT_STOP)
    default:
      return "(no event)";
  }
}

static inline const char *sigabbrev_np(int sig) {
  if (sig > 0 && sig < NSIG) return sys_signame[sig];

  return "(unknown)";
}

int get_program(int pid, char *buf, size_t size);

/* Shared by the monitor and the injector so both read the same meaning out of a
   waitpid status. */
#define STOPPED_WITH(st, sig, event) (WIFSTOPPED(st) && WSTOPSIG(st) == (sig) && ((st) >> 16) == (event))

#endif /* UTILS_H */
