//! Guards the loader/daemon protocol against one-sided drift.
//!
//! The loader (loader/src/) and the daemon (zygiskd/src/) each implement their
//! half of the wire protocol. The framing and the scalar readers are one
//! header both sides include (loader/src/include/socket_protocol.h); what stays
//! written twice is the action enum and the process flags, because each side
//! needs them as its own declarations. This check parses both trees and asserts
//! the two copies stay identical.
//!
//! The flags matter as much as the actions and are the easiest to drift: they
//! are plain macros duplicated in both trees (`zygiskd/src/constants.h` and
//! `loader/src/injector/module.h`), so adding a bit to one side alone still
//! compiles and only shows up at runtime as a flag the other half never sets or
//! never reads.
//!
//! Run in CI's host-test job; exits non-zero on the first divergence.
//!
//! Written without a regex crate on purpose: every pattern here is a fixed
//! shape over identifiers and whitespace, and hand-rolled scanning keeps the
//! tool's dependency list to what the signer already needs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The files each half of the protocol is declared in.
const PATHS: &[(&str, &str)] = &[
    ("daemon actions", "zygiskd/src/constants.h"),
    ("loader actions", "loader/src/include/daemon.h"),
    ("daemon flags", "zygiskd/src/constants.h"),
    ("loader flags", "loader/src/injector/module.h"),
];

fn main() -> ExitCode {
    // The paths below are relative to the repository root. Run from the crate
    // (cargo test) the working directory is tools/, so the root is one level up;
    // run from the repository the argument names it outright.
    let root = match std::env::args().nth(1) {
        Some(dir) => PathBuf::from(dir),
        None => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

            if cwd.join("zygiskd").is_dir() {
                cwd
            } else {
                cwd.join("..")
            }
        }
    };

    match run(&root) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(root: &Path) -> Result<bool, String> {
    let daemon_actions_text = read(root, "daemon actions")?;
    let loader_actions_text = read(root, "loader actions")?;

    let daemon_actions = enum_members(&daemon_actions_text, "DaemonSocketAction")?;
    let loader_actions = enum_members(&loader_actions_text, "rezygiskd_actions")?;

    let mut failed = false;

    if daemon_actions != loader_actions {
        failed = true;

        println!("ACTION MISMATCH between the daemon and the loader:");

        for index in 0..daemon_actions.len().max(loader_actions.len()) {
            let daemon = daemon_actions
                .get(index)
                .map(String::as_str)
                .unwrap_or("(missing)");
            let loader = loader_actions
                .get(index)
                .map(String::as_str)
                .unwrap_or("(missing)");

            let marker = if daemon == loader { "  " } else { "! " };
            println!("{marker}{index:2}  daemon={daemon:24} loader={loader}");
        }
    }

    let daemon_flags = flag_values(&read(root, "daemon flags")?);
    let loader_flags = flag_values(&read(root, "loader flags")?);

    if daemon_flags != loader_flags {
        failed = true;

        println!("FLAG MISMATCH between the daemon and the loader:");

        let names: BTreeSet<&String> = daemon_flags.keys().chain(loader_flags.keys()).collect();
        for name in names {
            let daemon = daemon_flags
                .get(name)
                .map(String::as_str)
                .unwrap_or("(missing)");
            let loader = loader_flags
                .get(name)
                .map(String::as_str)
                .unwrap_or("(missing)");

            if daemon != loader {
                println!("! {name:26} daemon={daemon:14} loader={loader}");
            }
        }
    }

    if !failed {
        println!(
            "protocol check ok: {} actions, {} flags",
            daemon_actions.len(),
            daemon_flags.len()
        );
    }

    Ok(!failed)
}

fn read(root: &Path, key: &str) -> Result<String, String> {
    let relative = PATHS
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, path)| *path)
        .ok_or_else(|| format!("no path registered for {key}"))?;

    let full = root.join(relative);
    std::fs::read_to_string(&full).map_err(|e| format!("cannot read {}: {e}", full.display()))
}

/// The members of `enum <name> { ... }`, comments removed.
///
/// A member is whatever sits between commas with the `= value` part dropped;
/// an empty item is a trailing comma or a blank line, not a member.
fn enum_members(text: &str, name: &str) -> Result<Vec<String>, String> {
    // `enum_body` already stripped the comments out of the whole file, so the
    // body it hands back needs no second pass.
    let body = enum_body(text, name).ok_or_else(|| format!("cannot find enum {name}"))?;

    Ok(body
        .split(',')
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(|item| item.split('=').next().unwrap_or(item).trim().to_string())
        .collect())
}

/// The text between an enum's braces, with the comments already out of the way.
///
/// Searching the raw text would let a commented-out declaration match first:
/// `/* enum rezygiskd_actions { FAKE, } */` names the type as convincingly as the
/// real one does. Comments become single spaces rather than nothing, so the
/// tokens either side of a removed comment stay separate.
///
/// The end is the first closing brace after the opening one, which is enough
/// here: neither enum nests a struct or another enum, so that is the end of the
/// enum rather than of something inside it.
fn enum_body(text: &str, name: &str) -> Option<String> {
    let stripped = strip_comments(text);
    let keyword = "enum";

    let mut from = 0;
    while let Some(at) = stripped[from..].find(keyword) {
        let keyword_at = from + at;
        let after = &stripped[keyword_at + keyword.len()..];

        // The type name has to be the next word, with any amount of space
        // between the keyword and it.
        let rest = match after.trim_start().strip_prefix(name) {
            Some(rest) => rest,
            None => {
                from = keyword_at + keyword.len();
                continue;
            }
        };

        // And then the body, with any space between the name and the brace.
        let body = match rest.trim_start().strip_prefix('{') {
            Some(body) => body,
            None => {
                from = keyword_at + keyword.len();
                continue;
            }
        };

        let close = body.find('}')?;
        return Some(body[..close].to_string());
    }

    None
}

/// Removes block and line comments, so a commented-out member is not read as
/// one and a comment cannot hide a brace.
///
/// A comment becomes a single space rather than nothing: `a/* x */b` has to stay
/// two tokens, and joining them would invent an identifier that was never there.
fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    'outer: while !rest.is_empty() {
        let bytes = rest.as_bytes();

        if bytes[0] == b'/' && bytes.len() > 1 {
            match bytes[1] {
                b'*' => {
                    // The block comment runs to its terminator; an unterminated
                    // one takes the rest of the text, which is what a C compiler
                    // does with it too.
                    match rest[2..].find("*/") {
                        Some(at) => {
                            out.push(' ');
                            rest = &rest[2 + at + 2..];
                            continue 'outer;
                        }
                        None => return out,
                    }
                }
                b'/' => {
                    // The line comment runs to the newline, which is kept so the
                    // two lines do not join.
                    match rest.find('\n') {
                        Some(at) => {
                            rest = &rest[at..];
                            continue 'outer;
                        }
                        None => return out,
                    }
                }
                _ => {}
            }
        }

        // One whole character, so multi-byte text survives.
        let ch = rest.chars().next().expect("rest is non-empty");
        out.push(ch);
        rest = &rest[ch.len_utf8()..];
    }

    out
}

/// The `PROCESS_*` flag macros as name -> bit number.
///
/// Both sides define them as `(1u << n)`, so comparing the bit catches a
/// renumbering as well as a rename. The shape is anchored on that on purpose:
/// `PROCESS_NAME_MAX_LEN` shares the prefix but is a buffer length only the
/// daemon declares, and `PRIVATE_MASK` composes flags without being one, so
/// neither is a flag to compare.
fn flag_values(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();

    for line in text.lines() {
        let line = line.trim_start();
        let Some(rest) = line.strip_prefix("#define") else {
            continue;
        };
        // `#define` has to be followed by whitespace, so a longer directive
        // like `#define_A` cannot match.
        if !rest.starts_with([' ', '\t']) {
            continue;
        }

        let rest = rest.trim_start();

        // The name runs to the next whitespace.
        let name_end = rest.find([' ', '\t']).unwrap_or(rest.len());
        let name = &rest[..name_end];
        if !name.starts_with("PROCESS_") || !is_identifier(name) {
            continue;
        }

        let value = rest[name_end..].trim_start();
        let Some(bit) = one_u_left_shift(value) else {
            continue;
        };

        out.insert(name.to_string(), bit.to_string());
    }

    out
}

/// The `n` in `(1u << n)`, if the text starts with exactly that shape.
///
/// Spacing is tolerated because both sides format it differently; anything else
/// is not a flag bit.
fn one_u_left_shift(text: &str) -> Option<u32> {
    let rest = text.strip_prefix('(')?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix("1u")?;
    let rest = rest.trim_start().strip_prefix("<<")?;
    let rest = rest.trim_start();

    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }

    rest[..end].parse().ok()
}

fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !text.as_bytes()[0].is_ascii_digit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_members_come_out_in_order() {
        let text =
            "enum rezygiskd_actions {\n  DAEMON_SOCKET_CONNECT,\n  DAEMON_SOCKET_PING,\n};\n";
        assert_eq!(
            enum_members(text, "rezygiskd_actions").unwrap(),
            vec!["DAEMON_SOCKET_CONNECT", "DAEMON_SOCKET_PING"]
        );
    }

    #[test]
    fn an_explicit_value_is_dropped() {
        let text = "enum e {\n  A,\n  B = 7,\n  C,\n};\n";
        assert_eq!(enum_members(text, "e").unwrap(), vec!["A", "B", "C"]);
    }

    #[test]
    fn comments_are_not_members() {
        let text = "enum e {\n  A,\n  // B,\n  /* C, */\n  D,\n};\n";
        assert_eq!(enum_members(text, "e").unwrap(), vec!["A", "D"]);
    }

    #[test]
    fn a_trailing_comma_is_not_an_empty_member() {
        let text = "enum e {\n  A,\n  B,\n};\n";
        assert_eq!(enum_members(text, "e").unwrap(), vec!["A", "B"]);
    }

    #[test]
    fn a_name_mentioned_in_a_comment_is_not_the_enum() {
        let text = "/* enum rezygiskd_actions { FAKE, } */\nenum rezygiskd_actions { REAL, };\n";
        assert_eq!(
            enum_members(text, "rezygiskd_actions").unwrap(),
            vec!["REAL"]
        );
    }

    #[test]
    fn a_missing_enum_is_an_error_not_a_panic() {
        assert!(enum_members("struct s {};", "nope").is_err());
    }

    #[test]
    fn only_bit_shift_flags_are_collected() {
        let text = concat!(
            "#define PROCESS_PID (1u << 0)\n",
            "#define PROCESS_DENYLISTED (1u << 1)\n",
            // Not a bit: a length and a mask.
            "#define PROCESS_NAME_MAX_LEN 256\n",
            "#define PRIVATE_MASK (PROCESS_PID | PROCESS_DENYLISTED)\n",
        );

        let flags = flag_values(text);

        assert_eq!(flags.get("PROCESS_PID").map(String::as_str), Some("0"));
        assert_eq!(
            flags.get("PROCESS_DENYLISTED").map(String::as_str),
            Some("1")
        );
        assert_eq!(flags.len(), 2);
    }

    #[test]
    fn a_renumbered_flag_is_caught() {
        let daemon = flag_values("#define PROCESS_PID (1u << 0)\n");
        let loader = flag_values("#define PROCESS_PID (1u << 5)\n");
        assert_ne!(daemon, loader);
    }

    #[test]
    fn spacing_inside_the_shift_is_tolerated() {
        assert_eq!(one_u_left_shift("(1u<<3)"), Some(3));
        assert_eq!(one_u_left_shift("( 1u << 3 )"), Some(3));
        assert_eq!(one_u_left_shift("(1u  <<  12)"), Some(12));
    }

    #[test]
    fn a_different_left_hand_side_is_not_a_bit() {
        assert_eq!(one_u_left_shift("(2u << 3)"), None);
        assert_eq!(one_u_left_shift("(1u >> 3)"), None);
        assert_eq!(one_u_left_shift("1u << 3"), None);
        assert_eq!(one_u_left_shift("(1u << )"), None);
    }

    #[test]
    #[test]
    fn comment_stripping_keeps_the_braces_balanced() {
        // A comment leaves a space, so the tokens either side stay separate.
        assert_eq!(strip_comments("a /* } */ b"), "a   b");
        assert_eq!(strip_comments("a // }\nb"), "a \nb");
        // An unterminated block comment takes the rest, as a compiler's does.
        assert_eq!(strip_comments("a /* unterminated"), "a ");
    }

    #[test]
    fn multi_byte_text_survives_comment_stripping() {
        // Pushing bytes one at a time would mangle anything above ASCII.
        assert_eq!(strip_comments("/* 中文 */ ok"), "  ok");
        assert_eq!(strip_comments("名字"), "名字");
    }
}
