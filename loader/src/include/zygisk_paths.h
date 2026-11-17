#ifndef ZYGISK_PATHS_H
#define ZYGISK_PATHS_H

/* Single source of truth for every path and socket name the loader and the
   daemon share; the literals used to be written on both sides.

   ZYGISK_TMP_PATH and ZYGISK_MODULE_ID are upgrade compatibility red lines:
   neither may change, or existing installs break. */

#define ZYGISK_TMP_PATH "/data/adb/rezygisk"
#define ZYGISK_MODULE_ID "rezygisk"
#define ZYGISK_MODULES_DIR "/data/adb/modules"
#define ZYGISK_MODULE_DIR ZYGISK_MODULES_DIR "/" ZYGISK_MODULE_ID

/* The daemon binary, the controller datagram socket the monitor listens on, and
   the stream socket the loader connects to. */
#define ZYGISKD_BIN ZYGISK_MODULE_DIR "/bin/zygiskd64"
#define ZYGISK_CONTROLLER_SOCKET ZYGISK_TMP_PATH "/init_monitor"
#define ZYGISK_CP_SOCKET ZYGISK_TMP_PATH "/cp64.sock"

/* What the daemon's last Zygisk Next plan came to, for the monitor to put on the
   module's card: the Zygisk Next path fails quietly in several ways that look
   identical from outside, and a release build keeps no log of it. */
#define ZYGISK_ZN_STATUS ZYGISK_TMP_PATH "/zn-status.txt"
#define ZYGISK_ZN_STATUS_TMP ZYGISK_ZN_STATUS ".tmp"

/* Files the monitor owns in the scratch directory. */
#define ZYGISK_STATE_JSON ZYGISK_TMP_PATH "/state.json"
#define ZYGISK_MODULE_PROP ZYGISK_MODULE_DIR "/module.prop"

/* The injector the ptracer loads into every target. The hiding pass matches this
   path to describe the mapping afterwards, so the two cannot be edited apart. */
#define ZYGISK_LOADER_LIB ZYGISK_MODULE_DIR "/lib64/libzygisk.so"

/* The memfd the Zygisk Next loader copies a module library into before dlopen:
   bionic rejects both the module path and a plain fd. It is also the name the
   library carries in a maps listing, so the loader and the hiding code have to
   agree on it. */
#define ZYGISK_ZN_MEMFD_NAME "zn-module"
#define ZYGISK_ZN_MEMFD "/memfd:" ZYGISK_ZN_MEMFD_NAME

#endif /* ZYGISK_PATHS_H */
