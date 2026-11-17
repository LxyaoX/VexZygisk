#include <stdbool.h>

#include "daemon.h"
#include "logging.h"
#include "misc.h"

#include "hook.h"
#include "ptrace_clear.h"
#include "zn_loader.h"

__attribute__((visibility("default")))
void entry(void *handle, void *addr, size_t size) {
  LOGD("VexZygisk library injected, version %s", ZKSU_VERSION);

  /* Kept for the teardown: this is the only moment the handle exists on this
     side of the ptrace boundary, since it came back from the dlopen in a
     register and nothing here could ask the linker for it again by value. */
  injector_handle = handle;

  start_addr = addr;
  block_size = size;

  LOGD("start plt hooking");

  hook_functions();

  /* One window for every target: the zygote's apps ask again for themselves, so
     what it can lose is only the modules naming the zygote itself. */
  zn_load_all_modules(ZN_PLAN_ATTEMPTS_TREE, REZYGISKD_RETRY_DELAY_US);

  struct kernel_version version = parse_kversion();
  if (version.major > 3 || (version.major == 3 && version.minor >= 8)) {
    LOGD("Supported kernel version %d.%d.%d, sending seccomp event", version.major, version.minor, version.patch);

    perform_ptrace_message_clear();
  }

  if (!rezygiskd_zygote_injected()) {
    LOGE("VexZygiskd is not running");

    return;
  }

  LOGD("Zygisk library execution done, addr: %p, size: %zu", addr, size);
}
