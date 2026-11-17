/* INFO: What the monitor injects, and who gets which isolation.

         Three string comparisons decide it, and all three have been wrong once:
         a device whose host binary is not the classic one was never injected at
         all, and an app zygote taken for an ordinary application took the
         in-place revert into a mount namespace everything below it inherits.
         They are pure, so the rules can be held still here instead of on a
         device that has to be rebooted to answer. */

#include <stdio.h>
#include <string.h>

#include "check.h"
#include "zygote_targets.h"

static void the_hosts_are_the_two_spellings(void) {
  CHECK(zygote_program_is_app_host("/system/bin/app_process64"),
        "the classic host was not recognised");
  CHECK(zygote_program_is_app_host("/apex/com.android.art/bin/artd"),
        "the ART host Android 15 moved to was not recognised");

  CHECK(!zygote_program_is_app_host("/system/bin/app_process32"),
        "the 32-bit host was taken as a target");
  CHECK(!zygote_program_is_app_host("/system/bin/app_process"),
        "a path one character short matched");
  CHECK(!zygote_program_is_app_host("app_process64"),
        "a bare file name matched a full path");
  CHECK(!zygote_program_is_app_host("/system/bin/app_process64 "),
        "a trailing space was ignored");
  CHECK(!zygote_program_is_app_host(""),
        "an empty path matched");
}

static void only_the_classic_binary_counts_as_a_restart(void) {
  CHECK(zygote_program_counts_as_restart("/system/bin/app_process64"),
        "the classic zygote does not count towards the crash-loop stop");

  CHECK(!zygote_program_counts_as_restart("/apex/com.android.art/bin/artd"),
        "the ART daemon's own execs count towards the crash-loop stop");
  CHECK(!zygote_program_counts_as_restart("/system/bin/app_process32"),
        "a 32-bit host counts towards the crash-loop stop");
}

static void an_app_zygote_is_named_by_its_suffix(void) {
  CHECK(zygote_process_is_app_zygote("webview_zygote"),
        "the WebView app zygote was not recognised");
  CHECK(zygote_process_is_app_zygote("com.example.app_zygote"),
        "a package's app zygote was not recognised");
  CHECK(zygote_process_is_app_zygote("a_zygote"),
        "the shortest name that can carry the suffix was not recognised");

  CHECK(!zygote_process_is_app_zygote("zygote"),
        "the zygote itself was taken for an app zygote");
  CHECK(!zygote_process_is_app_zygote("zygote64"),
        "a zygote spelling was taken for an app zygote");
  CHECK(!zygote_process_is_app_zygote("_zygote"),
        "the suffix alone was taken for a name");
  CHECK(!zygote_process_is_app_zygote("app_process64"),
        "the host binary was taken for an app zygote");
  CHECK(!zygote_process_is_app_zygote("usap32"),
        "an ordinary service was taken for an app zygote");
  CHECK(!zygote_process_is_app_zygote("com.example.zygote_app"),
        "a name that merely contains the suffix matched");
  CHECK(!zygote_process_is_app_zygote(""),
        "an empty name matched");
  CHECK(!zygote_process_is_app_zygote(NULL),
        "a NULL name matched");
}

int main(void) {
  the_hosts_are_the_two_spellings();
  only_the_classic_binary_counts_as_a_restart();
  an_app_zygote_is_named_by_its_suffix();

  if (g_failures != 0) {
    printf("%d check(s) failed\n", g_failures);

    return 1;
  }

  printf("zygote targets: all checks passed\n");

  return 0;
}
