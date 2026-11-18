#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include <dlfcn.h>
#include <link.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <elf.h>
#include <unistd.h>

#define LOG_TAG "zygisk-injector"

#include "misc.h"
#include "utils.h"
#include "zygisk_paths.h"

#ifndef ALIGN_UP
  #define ALIGN_UP(x, a) (((x) + ((a)-1)) & ~((a)-1))
#endif

/* INFO: Loads the injector with the target's own linker.

           The previous path hand-mapped the library with CSOLoader: the PT_LOAD
           segments, the relocations, and a jump to the entry - and nothing else.
           So DT_INIT_ARRAY was never walked and no constructor ran, and the
           object never appeared in the linker's soinfo list, which is what
           LSPosed probes when it reports "Zygisk Next API is unavailable" with
           the library plainly loaded.

           Letting the linker do it fixes both by construction: it walks
           DT_INIT_ARRAY itself and publishes a soinfo. */
/* INFO: The message dlopen left in the target, read back out of it. It is the
         only place the real reason (missing soname, bad ELF, denied namespace)
         shows up - this side sees a NULL and nothing else.

         Every step is best-effort: the point of calling it is that something
         already failed, so a step that fails here is reported and the original
         failure stands. */
static void log_remote_dlerror(int pid, struct user_regs_struct *regs, struct maps_info *map,
                               struct maps_info *local_map, void *return_addr) {
  /* INFO: Read dlerror's message out of the target. It is the only place the
            real reason (missing soname, bad ELF, denied namespace) shows up. */
  void *dlerror_addr = find_func_addr(local_map, map, "libdl.so", "dlerror");
  void *strlen_addr = find_func_addr(local_map, map, "libc.so", "strlen");

  if (dlerror_addr && strlen_addr) {
    uintptr_t msg = remote_call(pid, regs, (uintptr_t)dlerror_addr, (uintptr_t)return_addr, NULL, 0);

    if (msg) {
      long len_args[1] = { (long)msg };
      uintptr_t len = remote_call(pid, regs, (uintptr_t)strlen_addr, (uintptr_t)return_addr, len_args, 1);

      if (len > 0 && len < 512) {
        char err[513];

        if (read_proc(pid, msg, err, (size_t)len) == (ssize_t)len) {
          err[len] = '\0';
          LOGE("remote dlopen failed: %s", err);
        } else {
          LOGE("remote dlopen failed (could not read dlerror)");
        }
      }
    }
  }
}

static bool find_injected_range(int pid, const char *lib_path,
                                uintptr_t *out_base, size_t *out_size) {
  /* INFO: Where the injector was loaded, handed to entry() with the handle.
            The manual loader used to compute this pair from the layout it was
            about to map; with dlopen the mapping belongs to the linker, so it
            is recovered from the target's own maps instead. dladdr is
            deliberately not used here: it would write a Dl_info into the
            *target's* memory, which this process cannot read back through
            remote_call.

            The maps have to be re-read: `map` predates the dlopen, so the
            object is not in it yet. */
  char pid_str[11];
  snprintf(pid_str, sizeof(pid_str), "%d", pid);

  struct maps_info *post = parse_maps(pid_str);
  if (!post) {
    LOGE("failed to re-read the target maps after dlopen");

    return false;
  }

  /* The object is identified by dev+inode, not by path: a module that replaced
     its own file leaves the old one mapped under a "(deleted)" suffix, and a
     second mapping whose path merely shares the basename would be read as part
     of the injected block. Anonymous mappings carry inode 0, so they are
     excluded for free.

     The first pass still looks at the path, anchored at the start so a longer
     path with this one as a substring cannot match. */
  uintptr_t base = 0;
  size_t size = 0;
  dev_t lib_dev = 0;
  ino_t lib_inode = 0;

  for (size_t i = 0; i < post->length; i++) {
    const struct map_entry *m = &post->maps[i];

    if (m->inode == 0) continue;
    if (m->offset != 0) continue;
    if (!m->path || strncmp(m->path, lib_path, strlen(lib_path)) != 0) continue;

    lib_dev = m->dev;
    lib_inode = m->inode;

    break;
  }

  if (lib_inode != 0) {
    for (size_t i = 0; i < post->length; i++) {
      const struct map_entry *m = &post->maps[i];

      if (m->dev != lib_dev || m->inode != lib_inode) continue;

      if (!base) base = (uintptr_t)m->start;
      if (m->end > (uintptr_t)base + size) size = (size_t)(m->end - (uintptr_t)base);
    }
  }

  free_maps(post);

  if (!base) {
    LOGE("could not find the injected library in the target maps after dlopen");

    return false;
  }

  *out_base = base;
  *out_size = size;

  return true;
}

static bool dlopen_inject(int pid, struct user_regs_struct *regs, struct maps_info *map,
                          struct maps_info *local_map, const char *lib_path, void *return_addr) {
  void *dlopen_addr = find_func_addr(local_map, map, "libdl.so", "dlopen");
  if (!dlopen_addr) {
    LOGE("could not find dlopen in the target process");

    return false;
  }

  /* INFO: dlopen takes the path by pointer, so the string has to live in the
            target. It goes on the target's own stack, well below the frame the
            upcoming remote_call will use. */
  size_t path_len = strlen(lib_path) + 1;
  uintptr_t remote_path = regs->REG_SP - ALIGN_UP(path_len, 16);

  if (write_proc(pid, remote_path, lib_path, path_len) != (ssize_t)path_len) {
    LOGE("failed to write the library path into the target");

    return false;
  }

  regs->REG_SP = remote_path;

  long args[2] = {
    (long)remote_path,
    (long)RTLD_NOW
  };

  uintptr_t handle = remote_call(pid, regs, (uintptr_t)dlopen_addr, (uintptr_t)return_addr, args, 2);
  if (!handle) {
    log_remote_dlerror(pid, regs, map, local_map, return_addr);

    return false;
  }

  LOGI("remote dlopen succeeded, handle %p", (void *)handle);

  void *dlsym_addr = find_func_addr(local_map, map, "libdl.so", "dlsym");
  if (!dlsym_addr) {
    LOGE("could not find dlsym in the target process");

    return false;
  }

  /* INFO: "entry" is the injector's own export, the same symbol the manual
            loader used to resolve by hand. */
  static const char entry_sym[] = "entry";
  uintptr_t remote_entry_name = regs->REG_SP - ALIGN_UP(sizeof(entry_sym), 16);

  if (write_proc(pid, remote_entry_name, entry_sym, sizeof(entry_sym)) != (ssize_t)sizeof(entry_sym)) {
    LOGE("failed to write the entry symbol name into the target");

    return false;
  }

  regs->REG_SP = remote_entry_name;

  long dlsym_args[2] = {
    (long)handle,
    (long)remote_entry_name
  };

  uintptr_t entry = remote_call(pid, regs, (uintptr_t)dlsym_addr, (uintptr_t)return_addr, dlsym_args, 2);
  if (!entry) {
    LOGE("dlsym(\"entry\") failed in the target");

    return false;
  }

  LOGI("resolved injector entry at %p", (void *)entry);

  uintptr_t base = 0;
  size_t size = 0;

  if (!find_injected_range(pid, lib_path, &base, &size)) return false;

  LOGI("injected library base %p size %zu", (void *)base, size);

  /* INFO: Two arguments: the address and size of the injected block. The dlopen
            handle is deliberately not passed down. The teardown used to receive
            it and dlclose the library, which freed its soinfo while the linker
            list still walked it in load order - the mismatch a detector finds
            by deriving addresses from the allocator's page chain. The injector
            hides the mapping name in place instead and keeps the soinfo linked. */
  long entry_args[2] = {
    (long)base,
    (long)size
  };

  remote_call(pid, regs, entry, (uintptr_t)return_addr, entry_args, 2);

  return (uintptr_t)regs->REG_IP == (uintptr_t)return_addr;
}

bool inject_on_main(int pid, const char *lib_path, uintptr_t libc_init_target, uintptr_t libc_init_got_slot) {
  LOGI("injecting %s to zygote %d via GOT hook", lib_path, pid);

  /* INFO: From here until the slot is restored, every failure path has to put
            the resolved target back: leaving the poison in place means the
            next indirect call through that GOT faults, and a target resumed
            into that - detached or restarted - dies on the spot. The resolved
            address is the right value even though nothing was injected; the
            linker's lazy stub would work too, but this one is already known. */
  uintptr_t break_addr = (uintptr_t)-16;
  if (!ptrace_poke_uintptr(pid, libc_init_got_slot, break_addr)) {
    LOGE("Failed to patch GOT slot with break_addr");

    return false;
  }

  if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
    PLOGE("Failed to continue to GOT break");

    ptrace_poke_uintptr(pid, libc_init_got_slot, libc_init_target);

    return false;
  }

  int status = 0;
  wait_for_trace(pid, &status, __WALL);

  if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSEGV) {
    char status_str[64];
    parse_status(status, status_str, sizeof(status_str));

    LOGE("expected SIGSEGV on __libc_init GOT call, got: %s", status_str);

    ptrace_poke_uintptr(pid, libc_init_got_slot, libc_init_target);

    return false;
  }

  struct user_regs_struct regs = { 0 };
  if (!get_regs(pid, &regs)) {
    LOGE("Failed to get regs after GOT break");

    /* INFO: The slot still holds the poison from above. Nothing here can
              reset the register state - that needs the regs get_regs failed
              to read - but leaving the GOT pointing at -16 guarantees the next
              indirect call faults too, whether this target is detached with
              SIGCONT or restarted. Putting the resolved target back is the one
              part of the recovery that is still available. */
    ptrace_poke_uintptr(pid, libc_init_got_slot, libc_init_target);

    return false;
  }

  if (!ptrace_poke_uintptr(pid, libc_init_got_slot, libc_init_target)) {
    LOGE("Failed to restore __libc_init GOT slot");

    return false;
  }

  struct user_regs_struct backup;
  memcpy(&backup, &regs, sizeof(regs));

  char pid_str[11];
  snprintf(pid_str, sizeof(pid_str), "%d", pid);

  struct maps_info *map = parse_maps(pid_str);
  if (!map) {
    LOGE("Failed to parse remote maps after GOT break");

    return false;
  }

  struct maps_info *local_map = parse_maps("self");
  if (!local_map) {
    LOGE("Failed to parse local maps");

    free_maps(map);

    return false;
  }

  void *libc_return_addr = find_module_return_addr(map, "libc.so");

  if (!libc_return_addr) {
    LOGE("Failed to find a return address in the target");

    free_maps(local_map);
    free_maps(map);

    return false;
  }

  bool injected = dlopen_inject(pid, &regs, map, local_map, lib_path, libc_return_addr);

  free_maps(local_map);
  free_maps(map);

  if (!injected) {
    LOGE("Remote dlopen injection failed");

    backup.REG_IP = (long)libc_init_target;
    set_regs(pid, &backup);

    return false;
  }

  /* INFO: Restore from `backup`, not from `regs`: every remote call has been
             mutating `regs` (arguments, SP, and the BTYPE field remote_call
             clears), and the tracee has to resume with the register state it
             was interrupted in - the target validates its own BTI pad once it
             runs again. Only the instruction pointer is redirected, back to the
             real __libc_init now that the GOT slot holds it again. */
  backup.REG_IP = (long)libc_init_target;
  if (!set_regs(pid, &backup)) return false;

  LOGD("injection complete, instruction pointer reset to __libc_init (%p)", (void *)libc_init_target);

  return true;
}

#define WAIT_OR_DIE wait_for_trace(pid, &status, __WALL);
#define CONT_OR_DIE                           \
  if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) { \
    PLOGE("cont");                            \
                                              \
    return false;                             \
  }

bool trace_zygote(int pid, bool exit_kill) {
  LOGI("start tracing %d (tracer %d)", pid, getpid());

  int status = 0;

  struct kernel_version version = parse_kversion();

  /* EXITKILL keeps a tracer death from leaving a traced zygote behind, and
     TRACESECCOMP lets wait_for_trace skip seccomp events. EXITKILL is the
     caller's decision: it is the right trade for a zygote the monitor restarts
     anyway, and the first trace of a boot runs without it because a failure
     there is handled by detaching instead. */
  long seize_options = 0;
  if (version.major > 3 || (version.major == 3 && version.minor >= 8)) {
    seize_options = PTRACE_O_TRACESECCOMP;
    if (exit_kill) seize_options |= PTRACE_O_EXITKILL;
  }

  if (ptrace(PTRACE_SEIZE, pid, 0, seize_options) == -1) {
    PLOGE("seize");

    return false;
  }

  WAIT_OR_DIE;

  kill(pid, SIGCONT);
  ptrace(PTRACE_SYSCALL, pid, 0, 0);

  int syscall_stop_status;
  wait_for_ptrace_syscall_stop(pid, &syscall_stop_status);

  uintptr_t libc_init_got_slot = 0, libc_init_resolved = 0;
  if (!wait_linker_ready(pid, &libc_init_resolved, &libc_init_got_slot)) {
    LOGE("Failed to wait for linker ready for injection");

    ptrace(PTRACE_DETACH, pid, 0, SIGCONT);

    return false;
  }

  LOGD("Resolved __libc_init at %p (GOT slot %p)", (void *)libc_init_resolved, (void *)libc_init_got_slot);

  /* `status` intentionally still holds the stop observed right after the seize:
     the waits above only synchronized the syscall-stop and the linker. SEIZE
     stops with SIGSTOP, either as PTRACE_EVENT_STOP or as a plain SIGSTOP
     (event 0) when the monitor already stopped the target for the hand-off. */
  int stop_event = (int)((unsigned int)status >> 16);
  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP &&
      (stop_event == PTRACE_EVENT_STOP || stop_event == 0)) {
    char *lib_path = ZYGISK_LOADER_LIB;
    if (!inject_on_main(pid, lib_path, libc_init_resolved, libc_init_got_slot)) {
      LOGE("failed to inject");

      return false;
    }

    LOGD("inject done, continue process");
    if (kill(pid, SIGCONT)) {
      PLOGE("kill");

      return false;
    }

    CONT_OR_DIE
    WAIT_OR_DIE

    if (STOPPED_WITH(status, SIGTRAP, PTRACE_EVENT_STOP)) {
      CONT_OR_DIE
      WAIT_OR_DIE
    }

    if (STOPPED_WITH(status, SIGCONT, 0)) {
      LOGD("received SIGCONT");

      /* INFO: Due to kernel bugs, fixed in 5.16+, ptrace_message (msg of
             PTRACE_GETEVENTMSG) may not represent the current state of
             the process. Because we set some options, which alters the
             ptrace_message, we need to call PTRACE_SYSCALL to reset the
             ptrace_message to 0, the default/normal state.
        */
      ptrace(PTRACE_SYSCALL, pid, 0, 0);

      WAIT_OR_DIE

      ptrace(PTRACE_DETACH, pid, 0, SIGCONT);
    } else {
      char status_str[64];
      parse_status(status, status_str, sizeof(status_str));

      /* INFO: The injection is already complete, so this is a detach and not
                a failure: reporting one would have the caller kill an
                injected, working target. The stop's own signal is handed
                over on detach when there is one to hand - a delivery stop
                the target still owes - and nothing for a ptrace event,
                which is a notification and not a signal. */
      LOGW("Expected SIGTRAP or a direct SIGCONT after injection, found: %s; detaching", status_str);

      int event = (int)((unsigned int)status >> 16);
      int deliver = event == 0 && WIFSTOPPED(status) ? WSTOPSIG(status) : 0;

      ptrace(PTRACE_DETACH, pid, 0, deliver);

      return true;
    }
  } else {
    char status_str[64];
    parse_status(status, status_str, sizeof(status_str));

    LOGE("Expected SIGSTOP (event: EVENT_STOP), found: %s", status_str);

    ptrace(PTRACE_DETACH, pid, 0, 0);

    return false;
  }

  return true;
}
