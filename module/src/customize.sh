# shellcheck disable=SC2034
SKIPUNZIP=1

MIN_KSU_VERSION=@MIN_KSU_VERSION@
MIN_KSUD_VERSION=@MIN_KSUD_VERSION@

if [ "$BOOTMODE" ] && [ "$KSU" ]; then
  ui_print "- Installing from KernelSU app"
  ui_print "- KernelSU version: $KSU_KERNEL_VER_CODE (kernel) + $KSU_VER_CODE (ksud)"
  if ! [ "$KSU_KERNEL_VER_CODE" ] || [ "$KSU_KERNEL_VER_CODE" -lt "$MIN_KSU_VERSION" ]; then
    ui_print "*********************************************************"
    ui_print "! KernelSU version is too old!"
    ui_print "! Please update KernelSU to latest version"
    abort    "*********************************************************"
  fi
  if ! [ "$KSU_VER_CODE" ] || [ "$KSU_VER_CODE" -lt "$MIN_KSUD_VERSION" ]; then
    ui_print "*********************************************************"
    ui_print "! ksud version is too old!"
    ui_print "! Please update KernelSU Manager to latest version"
    abort    "*********************************************************"
  fi
else
  ui_print "*********************************************************"
  ui_print "! Install from recovery is not supported"
  ui_print "! Please install from KernelSU"
  abort    "*********************************************************"
fi

VERSION=$(grep_prop version "${TMPDIR}/module.prop")
ui_print "- Installing VexZygisk $VERSION"

# check android
if [ "$API" -lt 25 ]; then
  ui_print "! Unsupported sdk: $API"
  abort "! Minimal supported sdk is 25 (Android 7.1)"
else
  ui_print "- Device sdk: $API"
fi

# check architecture
if [ "$ARCH" = "x86" ] || [ "$ARCH" = "x64" ]; then
  abort "! x86 / x86_64 devices are not supported by VexZygisk"
fi

# INFO: 32-bit builds are gone. A 64-bit device never had its secondary
#         32-bit Zygote injected - the monitor skips it on purpose - so
#         dropping them costs nothing there, and a 32-bit device would be
#         left with nothing to install.
if [ "$ARCH" = "arm" ]; then
  abort "! 32-bit devices are not supported by VexZygisk"
fi

if [ "$ARCH" != "arm64" ]; then
  abort "! Unsupported platform: $ARCH"
fi

ui_print "- Device platform: $ARCH"

ui_print "- Extracting verify.sh"
unzip -o "$ZIPFILE" 'verify.sh' -d "$TMPDIR" >&2
if [ ! -f "$TMPDIR/verify.sh" ]; then
  ui_print "*********************************************************"
  ui_print "! Unable to extract verify.sh!"
  ui_print "! This zip may be corrupted, please try downloading again"
  abort    "*********************************************************"
fi
. "$TMPDIR/verify.sh"
extract "$ZIPFILE" 'customize.sh'  "$TMPDIR/.vunzip"
extract "$ZIPFILE" 'verify.sh'     "$TMPDIR/.vunzip"
extract "$ZIPFILE" 'sepolicy.rule' "$TMPDIR"

if [ "$KSU" ]; then
  ui_print "- Checking SELinux patches"
  if ! check_sepolicy "$TMPDIR/sepolicy.rule"; then
    ui_print "*********************************************************"
    ui_print "! Unable to apply SELinux patches!"
    ui_print "! Your kernel may not support SELinux patch fully"
    abort    "*********************************************************"
  fi
fi

# INFO: Stop a monitor left over from the previous install. It rewrites
#         module.prop on every status change, and a write landing while this
#         installer is replacing the file can leave a half-read copy behind.
if [ "$BOOTMODE" ]; then
  tracer=/data/adb/modules/rezygisk/bin/zygisk-ptrace64
  [ -f "$tracer" ] && "$tracer" ctl exit >/dev/null 2>&1

  killall -9 zygisk-ptrace64 >/dev/null 2>&1 || true
fi

ui_print "- Extracting module files"
extract "$ZIPFILE" 'module.prop'     "$MODPATH"
extract "$ZIPFILE" 'post-fs-data.sh' "$MODPATH"
extract "$ZIPFILE" 'uninstall.sh'    "$MODPATH"
extract "$ZIPFILE" 'action.sh'       "$MODPATH"
extract "$ZIPFILE" 'rezygisk.sh' "/data/adb/post-fs-data.d/"

# INFO: Everything in the archive is 0644 and extract does not bring an
#         executable bit in from the zip. KernelSU runs a stage script only
#         when the file carries one (module.rs, is_executable), so the two that
#         land in a stage directory are marked here - the same reason
#         late-load.sh and uninstall.sh are chmodded below.
chmod 0755 "$MODPATH/post-fs-data.sh" "/data/adb/post-fs-data.d/rezygisk.sh"

# INFO: Installed to late-load.d as well, not just post-fs-data.d. A late-loaded
#         KernelSU (the temporary-root / jailbreak flow) is injected after
#         post-fs-data has already passed, so post-fs-data.d is never reached
#         in that session and nothing would start the monitor: every Zygisk
#         module would stay dead while the manager keeps listing it. KernelSU
#         runs this stage from late_load.rs right after the injection, and
#         skips the directory entirely on a normal boot, where post-fs-data.d
#         already did the work.
#
#         Unlike rezygisk.sh this copy is not duplicated elsewhere: only the
#         KernelSU flavour has a late-load stage, so the APatch flavour ships
#         no counterpart.
#
#         chmod is explicit: KernelSU runs a stage script only when it carries
#         the executable bit (module.rs, is_executable), and the module tree is
#         not guaranteed to inherit one from the zip entry.
extract "$ZIPFILE" 'late-load.sh' "/data/adb/late-load.d/"
chmod 0755 "/data/adb/late-load.d/late-load.sh"

# INFO: KernelSU 2.x.x and below runs post-fs-data.d before mounting
#         the modules. This disallows us to clean our own module.prop.
#         To work around this, we utilize post-mount.d which runs after
#         mounting, and copy our post-fs-data.d script there.
#
# SOURCES:
#  - https://github.com/tiann/KernelSU/blob/6615068a987a12bbc6a3ad272b285cec7f594964/userspace/ksud/src/init_event.rs#L123
#  - https://github.com/tiann/KernelSU/blob/6615068a987a12bbc6a3ad272b285cec7f594964/userspace/ksud/src/init_event.rs#L161
#  - https://github.com/tiann/KernelSU/blob/6615068a987a12bbc6a3ad272b285cec7f594964/userspace/ksud/src/init_event.rs#L212-L217
mkdir -p /data/adb/post-mount.d
cp "/data/adb/post-fs-data.d/rezygisk.sh" "/data/adb/post-mount.d/rezygisk.sh"
chmod 0755 "/data/adb/post-mount.d/rezygisk.sh"

cp "$MODPATH/module.prop" "$MODPATH/module.prop.bak"

# INFO: The monitor was stopped above, so nothing is left to put the update
#         notice on the card between now and the next reboot. Its own EXIT
#         handler cannot do it: ctl exit is a fire-and-forget UDP datagram and
#         the killall lands before the monitor can write, and the extract above
#         would overwrite the line even if it did. Write it here, after both the
#         extract and the pristine backup, so .bak stays clean and the first
#         boot's rezygisk.sh restores pristine before the new monitor redraws.
if [ -f "$MODPATH/module.prop" ]; then
  sed -i 's/^description=/description=[⏸ an update was installed - reboot to start it] /' "$MODPATH/module.prop"
fi

chmod +x "$MODPATH/uninstall.sh" "$MODPATH/action.sh"

mv "$TMPDIR/sepolicy.rule" "$MODPATH"

mkdir "$MODPATH/bin"

ui_print "- Extracting arm64-v8a libraries"
mkdir "$MODPATH/lib64"

extract "$ZIPFILE" "bin/arm64-v8a/zygiskd" "$MODPATH/bin" true
mv "$MODPATH/bin/zygiskd" "$MODPATH/bin/zygiskd64"
extract "$ZIPFILE" "lib/arm64-v8a/libzygisk.so" "$MODPATH/lib64" true
extract "$ZIPFILE" "lib/arm64-v8a/libzygisk_ptrace.so" "$MODPATH/bin" true
mv "$MODPATH/bin/libzygisk_ptrace.so" "$MODPATH/bin/zygisk-ptrace64"

ui_print "- Setting permissions"
set_perm_recursive "$MODPATH/bin" 0 0 0755 0755
set_perm_recursive "$MODPATH/lib64" 0 0 0755 0644 u:object_r:system_lib_file:s0

# INFO: If Huawei's Maple is enabled, system_server is created in a way that is
#         out of Zygisk's control, so the property is turned off for this
#         module's boot. It is read through getprop: grep_prop looks a property
#         up in a prop file and reads stdin when it is given none, which is why
#         this check never fired.
HUAWEI_MAPLE_ENABLED=$(getprop ro.maple.enable)
if [ "$HUAWEI_MAPLE_ENABLED" = "1" ]; then
  ui_print "- Add ro.maple.enable=0"
  echo "ro.maple.enable=0" >>"$MODPATH/system.prop"
fi
