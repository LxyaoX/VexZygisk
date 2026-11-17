#ifndef ZN_CONTROL_PROTOCOL_H
#define ZN_CONTROL_PROTOCOL_H

/* The wire contract of the HyperOS runtime's control session: the loader writes
   reports on it (loader/src/common/daemon.c), the daemon reads them
   (zygiskd/src/zygiskd.c). One header, because two copies of a record agree only
   until somebody edits one, and a session out of step looks from outside like a
   module that was never told anything.

   The action byte that introduces a record is not here: it belongs to the enum
   both halves declare and check-protocol already compares. */

#include <stddef.h>
#include <stdint.h>

/* How long a module id may be, which is how long a module directory name may be.
   Both halves bound a report with it; a longer one ends the session. */
#define ZN_CONTROL_MODULE_ID_MAX (256 + 1)

/* Two 32-bit fields, not uint32 + size_t: the latter carries padding, so a
   writer sending the struct and a reader taking the fields one by one would
   disagree about the distance between them. At 8 bytes this is the same record
   on every ABI this fork ships, and a module id fits a uint32 many times over. */
struct zn_control_report_header {
  uint32_t pid;
  uint32_t module_id_len;
};

/* Checked, not assumed: a different layout would not fail to build, it would
   read the wrong fields. Both spellings, because the loader is C18 and the
   daemon C99. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct zn_control_report_header) == 2 * sizeof(uint32_t),
               "a report header is two 32-bit fields with no padding");
_Static_assert(offsetof(struct zn_control_report_header, pid) == 0,
               "the reporting pid is the first field of a report header");
_Static_assert(offsetof(struct zn_control_report_header, module_id_len) == sizeof(uint32_t),
               "the module id length follows the pid");
#else
typedef char zn_control_report_header_must_be_two_uint32[(sizeof(struct zn_control_report_header) == 2 * sizeof(uint32_t)) ? 1 : -1];
typedef char zn_control_report_pid_must_come_first[(offsetof(struct zn_control_report_header, pid) == 0) ? 1 : -1];
typedef char zn_control_report_len_must_follow_the_pid[(offsetof(struct zn_control_report_header, module_id_len) == sizeof(uint32_t)) ? 1 : -1];
#endif

/* The bytes one report occupies, its action byte excluded. */
static inline size_t zn_control_report_size(size_t module_id_len) {
  return sizeof(struct zn_control_report_header) + module_id_len;
}

#endif /* ZN_CONTROL_PROTOCOL_H */
