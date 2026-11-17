#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#include <sys/types.h>

#include "../constants.h"

/* The backend the daemon was built for. Only the matching member is compiled in,
   so the switches and the name table cannot carry the other root solution. */
#ifdef ROOT_IMPL_APATCH
enum root_impls {
  RootAPatch
};
#else
enum root_impls {
  RootKernelSU
};
#endif

struct root_impl_state {
  enum RootImplState state;
};

struct root_impl {
  enum root_impls impl;
};

/* The display name sits next to the kind so the length follows the string that
   is actually compiled in: sizeof("KernelSU") would overflow on a longer name. */
#ifdef ROOT_IMPL_APATCH
  #define ROOT_IMPL_KIND RootAPatch
  #define ROOT_IMPL_NAME "APatch"
#else
  #define ROOT_IMPL_KIND RootKernelSU
  #define ROOT_IMPL_NAME "KernelSU"
#endif

#define LONGEST_ROOT_IMPL_NAME sizeof(ROOT_IMPL_NAME)

/* Three answers, not two: both backends can be asked before they can answer
   (KernelSU before a manager is crowned, APatch before its scan settles), and
   "no" in that moment is read by the loader as "ordinary app" - which gets the
   root mounts reverted out of its own namespace. */
enum uid_manager_state {
  UID_MANAGER_NO = 0,
  UID_MANAGER_YES = 1,
  UID_MANAGER_UNKNOWN = 2
};

void root_impls_setup(void);

void get_impl(struct root_impl *uimpl);

void uid_query_root(uid_t uid, bool *granted_root, bool *should_umount);

enum uid_manager_state uid_is_manager(uid_t uid);

void root_impl_cleanup(void);

#endif /* COMMON_H */
