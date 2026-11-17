#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <stdbool.h>
#include <stdint.h>

#define PROCESS_NAME_MAX_LEN (256 + 1)

#define ZYGOTE_INJECTED 4
#define DAEMON_SET_INFO 6
/* One module record of a DAEMON_SET_INFO announcement - a wire value shared with
   the monitor's enum in loader/src/ptracer/monitor.h. */
#define DAEMON_MODULE_ENTRY 9

/* Plain macros rather than a typed enum: 1u << 31 does not fit an int, and a
   fixed underlying type is a C23 extension. */
#define PROCESS_GRANTED_ROOT (1u << 0)
#define PROCESS_ON_DENYLIST (1u << 1)
/* Whether any Zygisk Next module exists at all, so a device without one skips
   the per-fork ReadZnModules round trip. A global fact from the last module
   load, never passed on to modules (the loader strips it). */
#define PROCESS_ZN_PRESENT (1u << 2)
#define PROCESS_IS_MANAGER (1u << 27)
#define PROCESS_ROOT_IS_APATCH (1u << 28)
#define PROCESS_ROOT_IS_KSU (1u << 29)
#define PROCESS_IS_FIRST_STARTED (1u << 31)

enum DaemonSocketAction {
  ZygoteInjected         = 0,
  GetProcessFlags        = 1,
  GetInfo                = 2,
  ReadModules            = 3,
  RequestCompanionSocket = 4,
  GetModuleDir           = 5,
  ZygoteRestart          = 6,
  UpdateMountNamespace   = 7,
  RemoveModule           = 8,
  ReadZnModules          = 9,
  SpawnZnCompanion       = 10,
  OpenZnControlSession   = 11,
  ReportZnRuntime        = 12
};

/* Two states, not four: how the implementation was found is answered by whether
   it exists at all. */
enum RootImplState {
  Supported,
  Inexistent
};

/* The clean namespace is the only one the loader asks for: what a denylisted
   process is switched into when the in-place revert could not be applied. */
enum MountNamespaceState {
  Clean
};

#endif /* CONSTANTS_H */
