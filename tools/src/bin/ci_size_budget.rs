//! Fails when a built binary grows past its size budget.
//!
//! libzygisk.so statically links its engines (csoloader, PLTI and the LZMA
//! decoder), so a careless dependency can balloon it unnoticed.
//! The limits sit roughly 15% above the sizes measured when the budget was
//! introduced; raise them deliberately when a feature genuinely needs the
//! space, and re-measure both flavours when the loader's dependency set
//! changes.
//!
//! Usage: ci-size-budget [root ...]
//!
//! With no arguments every entry is checked; with arguments only the entries
//! below one of the given build-tree roots (e.g. build, build-apatch).

use std::path::Path;
use std::process::ExitCode;

use vex_tools::{is_under_roots, size_kib, strip_trailing_sep};

/// Budget in KiB, keyed by the path of the built artefact.
const BUDGET_KIB: &[(&str, u64)] = &[
    (
        "build/obj/release/loader/arm64-v8a/stripped/libzygisk.so",
        430,
    ),
    (
        "build/obj/release/loader/arm64-v8a/stripped/libzygisk_ptrace.so",
        100,
    ),
    ("build/obj/release/zygiskd/arm64-v8a/zygiskd", 56),
    (
        "build-apatch/obj/release/loader/arm64-v8a/stripped/libzygisk.so",
        430,
    ),
    (
        "build-apatch/obj/release/loader/arm64-v8a/stripped/libzygisk_ptrace.so",
        100,
    ),
    ("build-apatch/obj/release/zygiskd/arm64-v8a/zygiskd", 60),
];

fn main() -> ExitCode {
    let roots: Vec<String> = std::env::args()
        .skip(1)
        .map(|a| strip_trailing_sep(&a).to_string())
        .collect();
    let roots: Vec<&str> = roots.iter().map(String::as_str).collect();

    let mut failed = false;

    for (path, limit) in sorted_budget() {
        if !is_under_roots(path, &roots) {
            continue;
        }

        let Some(actual) = size_kib(Path::new(path)) else {
            println!("MISSING                {path}");
            failed = true;
            continue;
        };

        let over = actual > *limit;
        failed |= over;

        // The Python's fields are width 6, separated by single spaces.
        println!(
            "{actual:6} KiB / {limit:6} KiB  {}  {path}",
            if over { "OVER" } else { "ok  " }
        );
    }

    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// The budget table in a stable order.
///
/// The Python iterated `sorted(BUDGET_KIB.items())`, which orders by path. The
/// order is only for reproducible output - the pass/fail result does not depend
/// on it - so sorting here is what keeps the log identical between runs.
fn sorted_budget() -> Vec<(&'static str, &'static u64)> {
    let mut entries: Vec<(&'static str, &'static u64)> = BUDGET_KIB
        .iter()
        .map(|(path, limit)| (*path, limit))
        .collect();
    entries.sort_by_key(|(path, _)| *path);
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_is_sorted_by_path() {
        let sorted = sorted_budget();
        let mut paths: Vec<&str> = sorted.iter().map(|(p, _)| *p).collect();
        paths.sort_unstable();
        assert_eq!(paths, sorted.iter().map(|(p, _)| *p).collect::<Vec<_>>());
    }

    #[test]
    fn every_build_tree_is_covered() {
        for tree in ["build", "build-apatch"] {
            let covered = sorted_budget()
                .iter()
                .filter(|(p, _)| is_under_roots(p, &[tree]))
                .count();
            assert_eq!(covered, 3, "{tree} should have three budgeted artefacts");
        }
    }

    #[test]
    fn an_unknown_root_checks_nothing() {
        assert_eq!(
            sorted_budget()
                .iter()
                .filter(|(p, _)| is_under_roots(p, &["nope"]))
                .count(),
            0
        );
    }
}
