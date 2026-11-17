//! The `zygisk-ptrace64` command line front end.
//!
//! This is the Rust replacement for `loader/src/ptracer/main.c`. It owns
//! argument parsing, the banner, and the usage text; everything a subcommand
//! actually *does* still lives in the C engine next to it (`init_monitor`,
//! `trace_zygote`, `send_control_command`, `rezygiskd_get_info`), which is
//! linked into the same shared object. The split is deliberate: the engine is
//! ptrace, /proc parsing and socket code that has nothing to do with a CLI, and
//! moving it is a different job with a different risk.
//!
//! What this file does own is the part that was easy to get wrong in C: the
//! subcommand grammar. `trace` took a pid that had to be validated *before*
//! reaching `kill()`, because a parse that yields 0 signals the whole process
//! group.

use std::ffi::{c_char, c_int, CStr, CString};
use std::process::ExitCode;

// The version banner, `ZKSU_VERSION` from the C side.
//
// Passed in by the build rather than duplicated: two spellings of the version
// in one binary is exactly the drift this file exists to remove.
extern "C" {
    static ZKSU_VERSION: *const c_char;
}

// The engine, declared here rather than generated: five functions, and a
// bindgen step would be more machinery than the declarations are worth.
extern "C" {
    fn init_monitor();

    /// Returns 0 when the trace failed.
    fn trace_zygote(pid: c_int) -> c_int;

    fn send_control_command(command: c_int) -> c_int;

    fn rezygiskd_zygote_restart();

    fn rezygiskd_get_info(info: *mut RezygiskInfo);
    fn free_rezygisk_info(info: *mut RezygiskInfo);
}

/// `enum rezygiskd_command` from daemon.h.
const COMMAND_START: c_int = 0;
const COMMAND_STOP: c_int = 1;
const COMMAND_EXIT: c_int = 2;

/// `enum root_impl` from daemon.h. The values are the ones the KSU build
/// compiles with; the APatch build swaps the variant but the CLI only prints.
const ROOT_IMPL_KERNELSU: c_int = 0;
const ROOT_IMPL_APATCH: c_int = 1;

/// The module list is a fixed-size array in the middle of the struct, so it has
/// to be laid out here rather than behind a Vec. 128 entries matches
/// `MAX_MODULES` on the C side.
const MAX_MODULES: usize = 128;

/// `struct module_list` from daemon.h.
#[repr(C)]
struct ModuleList {
    modules_count: usize,
    modules: [*const c_char; MAX_MODULES],
}

/// `struct rezygisk_info` from daemon.h.
///
/// Zeroed before use exactly as the C did with `= { 0 }`: the daemon fills what
/// it knows and leaves the rest, so a field the daemon did not set must read as
/// zero rather than as whatever was on the stack.
#[repr(C)]
struct RezygiskInfo {
    running: bool,
    pid: c_int,
    root_impl: c_int,
    modules: ModuleList,
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let program = argv
        .first()
        .map(String::as_str)
        .unwrap_or("zygisk-ptrace64");

    println!("The VexZygisk Tracer {}\n", version());

    let args = &argv[1..];
    let command = args.first().map(String::as_str);

    match (command, args.len()) {
        (Some("monitor"), _) => {
            cut_stdout();
            // SAFETY: init_monitor is the monitor's own entry point and does not
            // take arguments; the C main called it the same way.
            unsafe { init_monitor() };
            ExitCode::SUCCESS
        }

        (Some("trace"), n) if n >= 2 => dispatch_trace(args),

        (Some("ctl"), n) if n >= 2 => dispatch_ctl(args),

        (Some("version"), _) => {
            println!("[VexZygisk]: {}", version());
            ExitCode::SUCCESS
        }

        (Some("info"), _) => dispatch_info(),

        _ => {
            print_usage(program);
            ExitCode::FAILURE
        }
    }
}

fn dispatch_trace(args: &[String]) -> ExitCode {
    let pid_arg = &args[1];
    let do_restart = args[2..].iter().any(|a| a == "--restart");

    if do_restart {
        // SAFETY: takes no arguments; the C main called it the same way.
        unsafe { rezygiskd_zygote_restart() };
    }

    // Validated before use: a bogus pid would otherwise reach the kill below as
    // 0, which signals the whole process group. The C used strtol with base 0,
    // so 0x-prefixed hex is accepted here as well.
    let pid = match parse_pid(pid_arg) {
        Some(pid) => pid,
        None => {
            println!("[VexZygisk]: Invalid pid \"{pid_arg}\"");
            return ExitCode::FAILURE;
        }
    };

    // SAFETY: trace_zygote only reads the pid it is handed.
    if unsafe { trace_zygote(pid) } == 0 {
        // A failed zygote trace must not leave a broken zygote running.
        signal_failed_trace(pid, do_restart);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

/// Parses a pid the way `strtol(arg, &end, 0)` did.
///
/// Base 0 means a leading `0x` is hex and a leading `0` is octal; anything else
/// is decimal. The whole string has to be consumed, so `123abc` is rejected -
/// which is what the C checked with `*pid_end != '\0'`.
fn parse_pid(arg: &str) -> Option<c_int> {
    let text = arg.trim();
    if text.is_empty() {
        return None;
    }

    let (digits, radix) = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(rest) => (rest, 16),
        None => match text.strip_prefix('0') {
            // "0" itself is a valid pid written with a redundant leading zero;
            // an empty remainder is left to the decimal path.
            Some(rest) if !rest.is_empty() => (rest, 8),
            _ => (text, 10),
        },
    };

    if digits.is_empty() {
        return None;
    }

    let pid = c_int::from_str_radix(digits, radix).ok()?;

    // The C tested `pid <= 0 || pid > INT_MAX`.
    (pid > 0).then_some(pid)
}

/// Detaches and resumes a tracee whose trace failed, or kills it.
///
/// On Android both calls go through libc, which the C reached with `ptrace()` and
/// `kill()` from `<signal.h>`.
fn signal_failed_trace(pid: c_int, kill_it: bool) {
    const SIGKILL: c_int = 9;

    if kill_it {
        // SAFETY: kill() on a pid we just failed to trace; the C did the same,
        // and the pid was validated as positive before it got here.
        unsafe { libc_kill(pid, SIGKILL) };
    } else {
        // SAFETY: PTRACE_DETACH on a tracee of ours, followed by SIGCONT so it
        // resumes rather than staying stopped.
        unsafe {
            libc_ptrace(
                PTRACE_DETACH,
                pid,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            libc_kill(pid, SIGCONT);
        }
    }
}

// Declared here rather than pulling in the libc crate: two symbols, and the
// crate would be a heavier dependency than the whole front end.
extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: c_int, sig: c_int) -> c_int;

    #[link_name = "ptrace"]
    fn libc_ptrace(
        request: c_int,
        pid: c_int,
        addr: *mut core::ffi::c_void,
        data: *mut core::ffi::c_void,
    ) -> c_int;
}

/// PTRACE_DETACH, kept next to its only use.
const PTRACE_DETACH: c_int = 17;

/// SIGCONT, kept next to its only use.
const SIGCONT: c_int = 18;

fn dispatch_ctl(args: &[String]) -> ExitCode {
    let command = match args[1].as_str() {
        "start" => COMMAND_START,
        "stop" => COMMAND_STOP,
        "exit" => COMMAND_EXIT,
        _ => {
            let program = std::env::args()
                .next()
                .unwrap_or_else(|| "zygisk-ptrace64".to_string());
            println!("[VexZygisk]: Usage: {program} ctl <start|stop|exit>");
            return ExitCode::FAILURE;
        }
    };

    // SAFETY: send_control_command writes a single datagram to the daemon's
    // control socket and returns -1 on failure; it reads nothing from us.
    if unsafe { send_control_command(command) } == -1 {
        println!("[VexZygisk]: Failed to send the command, is the daemon running?");
        return ExitCode::FAILURE;
    }

    println!("[VexZygisk]: command sent");
    ExitCode::SUCCESS
}

fn dispatch_info() -> ExitCode {
    // SAFETY: RezygiskInfo is a plain repr(C) struct with no invalid bit
    // patterns, so an all-zero value is a valid one - which is what the C's
    // `= { 0 }` produced before this file took the subcommand over.
    let mut info = unsafe { std::mem::zeroed::<RezygiskInfo>() };

    // SAFETY: info is a correctly laid out, zeroed struct of the size the C
    // expects, and free_rezygisk_info is the C's own release for it.
    unsafe {
        rezygiskd_get_info(&mut info);

        if !info.running {
            println!("[VexZygisk]: The daemon is not running");
            // The C freed the info before returning in this case too, so the
            // release runs even though nothing was printed.
            free_rezygisk_info(&mut info);
            return ExitCode::FAILURE;
        }

        println!("Daemon process PID: {}", info.pid);

        match info.root_impl {
            ROOT_IMPL_APATCH => println!("Root implementation: APatch"),
            ROOT_IMPL_KERNELSU => println!("Root implementation: KernelSU"),
            other => println!("Root implementation: unknown ({other})"),
        }

        let modules = &info.modules;
        if modules.modules_count != 0 {
            println!("Modules: {}", modules.modules_count);

            for index in 0..modules.modules_count.min(MAX_MODULES) {
                // SAFETY: the daemon wrote these pointers and the count says how
                // many are valid; each is a NUL-terminated string it owns.
                let name = CStr::from_ptr(modules.modules[index]);
                println!(" - {}", name.to_string_lossy());
            }
        } else {
            println!("Modules: N/A");
        }

        free_rezygisk_info(&mut info);
    }

    ExitCode::SUCCESS
}

fn print_usage(program: &str) {
    print!(
        "Available commands:\n\
         - monitor\n\
         - trace <pid> [--restart]\n\
         - ctl <start|stop|exit>\n\
         - version: Shows the version of VexZygisk.\n\
         - info: Shows information about the created daemon/injection.\n\
         \n\
         <...>: Obligatory\n\
         [...]: Optional\n"
    );
    let _ = program;
}

/// Redirects stdout to /dev/null.
///
/// stdout is the module script's pipe, drained into the root manager's log; the
/// monitor is long-lived and its findings go to logd, so the pipe side channel
/// is cut at startup instead of turning every status line into a wakeup of the
/// log drainer.
///
/// `freopen` rather than a Rust `File` + `dup2`: the C did this, and the point
/// is that the already-installed buffer is discarded with the old descriptor
/// rather than merely pointed elsewhere. The failure is deliberately ignored —
/// keeping the inherited stdout is better than exiting, which is what the C
/// documented too.
fn cut_stdout() {
    const O_WRONLY: c_int = 1;

    let Ok(path) = CString::new("/dev/null") else {
        return;
    };

    // SAFETY: `stdout` is the FILE* freopen's third argument takes, and it is
    // open for writing at this point - the C wrote the banner to it.
    unsafe {
        let stream = libc_stdout();
        libc_freopen(path.as_ptr(), O_WRONLY, stream);
    }
}

extern "C" {
    #[link_name = "freopen"]
    fn libc_freopen(
        path: *const c_char,
        mode: c_int,
        stream: *mut core::ffi::c_void,
    ) -> *mut core::ffi::c_void;

    #[link_name = "stdout"]
    fn libc_stdout() -> *mut core::ffi::c_void;
}

/// The version string the C side was compiled with.
fn version() -> String {
    // SAFETY: ZKSU_VERSION is a static NUL-terminated string set at link time.
    unsafe { CStr::from_ptr(ZKSU_VERSION) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_decimal_pid_parses() {
        assert_eq!(parse_pid("1234"), Some(1234));
    }

    #[test]
    fn a_hex_pid_parses_the_way_strtol_base_zero_did() {
        assert_eq!(parse_pid("0x1f"), Some(31));
        assert_eq!(parse_pid("0X1F"), Some(31));
    }

    #[test]
    fn a_leading_zero_is_octal() {
        assert_eq!(parse_pid("0755"), Some(0o755));
    }

    #[test]
    fn zero_and_negatives_are_rejected() {
        // The C's `pid <= 0` test: a zero would reach kill() and signal the
        // whole process group.
        assert_eq!(parse_pid("0"), None);
        assert_eq!(parse_pid("-1"), None);
        assert_eq!(parse_pid("-1234"), None);
    }

    #[test]
    fn a_trailing_garbage_pid_is_rejected() {
        // The C checked `*pid_end != '\0'` for exactly this.
        assert_eq!(parse_pid("123abc"), None);
        assert_eq!(parse_pid("12 34"), None);
        assert_eq!(parse_pid("1234x"), None);
    }

    #[test]
    fn an_empty_or_malformed_pid_is_rejected() {
        assert_eq!(parse_pid(""), None);
        assert_eq!(parse_pid("   "), None);
        assert_eq!(parse_pid("abc"), None);
        assert_eq!(parse_pid("0x"), None);
    }

    #[test]
    fn a_pid_beyond_int_max_is_rejected() {
        assert_eq!(parse_pid("99999999999999"), None);
    }
}
