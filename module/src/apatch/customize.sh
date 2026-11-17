# shellcheck disable=SC2034
SKIPUNZIP=1

MIN_APATCH_VERSION=@MIN_APATCH_VERSION@

if [ "$BOOTMODE" ] && [ "$APATCH" ]; then
  ui_print "- Installing from APatch app"
  if ! [ "$APATCH_VER_CODE" ] || [ "$APATCH_VER_CODE" -lt "$MIN_APATCH_VERSION" ]; then
    ui_print "*********************************************************"
    ui_print "! APatch version is too old!"
    ui_print "! Please update APatch to the latest version"
    abort    "*********************************************************"
  fi
else
  ui_print "*********************************************************"
  ui_print "! Install from recovery is not supported"
  ui_print "! Please install from APatch"
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
#         executable bit in from the zip, while the stage directory is only
#         run when the script carries one.
chmod 0755 "$MODPATH/post-fs-data.sh" "/data/adb/post-fs-data.d/rezygisk.sh"

# INFO: The KernelSU flavour copies rezygisk.sh into post-mount.d as well, a
#         stage the APatch flavour never uses. A switch from one flavour to
#         the other would otherwise leave that copy running at every boot,
#         resetting module.prop to a stale pristine state.
rm -f /data/adb/post-mount.d/rezygisk.sh

# INFO: The KernelSU flavour also installs late-load.sh into late-load.d, the
#         stage its own late-loaded root runs. APatch has no such stage, so a
#         switch from the KernelSU flavour has to clear that copy here —
#         leaving it would start a monitor APatch never drives.
rm -f /data/adb/late-load.d/late-load.sh

# INFO: APatch resolves module sepolicy.rule on the next boot through its own
#         boot stage, so there is no install-time policy check as KernelSU
#         does; the rule simply ships with the module.
mv "$TMPDIR/sepolicy.rule" "$MODPATH"

# INFO: rezygisk.sh (moved to post-fs-data.d) resets this module's module.prop
#         to its pristine state whenever it runs, so the pristine copy is kept
#         at install time exactly like the KernelSU flavour does.
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
