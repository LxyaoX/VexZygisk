//! The Rust half of VexZygisk's loader.
//!
//! Nothing here owns a device resource, calls into ART, or knows what a
//! zygote is. What lives in this crate is the part of the loader that reads
//! bytes an untrusted file supplied and decides what they mean - the ELF
//! symbol lookups today - and the point of moving that half is that the C
//! version had to say "and if this offset is past the end, give up" at every
//! step, by hand, in a function that also had to remember to free what it
//! allocated on the way out. Slices and `Option` say both of those once.
//!
//! The C side keeps what is genuinely its own: mapping the file, reading the
//! process maps to find the load base, and decompressing `.gnu_debugdata`
//! through the xz decoder it already links. This crate is handed the tables
//! that come out of that and answers one question - which address does this
//! symbol name have - through the same ABI the C functions had, so no caller
//! changes.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

// INFO: `got` is compiled under `cfg(test)` too: its parsing logic reads
//       through the `Image` trait, and only the descriptor wrapper and the
//       exported entry point - the pieces that reach `pread64` - are kept to
//       the device build. The host suite walks a synthetic image through the
//       same code, which is where a relocation-stride bug would otherwise
//       live unseen.
mod got;
mod hash;
mod lookup;
mod slice_ext;

#[cfg(not(test))]
pub use got::vexcore_got_offset;
pub use hash::{vexcore_elf_hash, vexcore_gnu_hash};
pub use lookup::{vexcore_elf_lookup, vexcore_gnu_lookup, Elf64Sym};

/// There is no unwinding in an injected process: a panic that unwound would
/// have to run destructors across frames the C side is holding state in, and
/// the libraries an app loads are not built to survive that. `panic = "abort"`
/// in the manifest already turns every panic into an abort; this handler is
/// what that abort goes through, so the panic machinery never has to find a
/// personality routine that a `no_std` image does not have.
///
/// It is absent under `cfg(test)` because the test harness is a `std` binary
/// and brings its own.
#[cfg(not(test))]
#[panic_handler]
fn on_panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: `abort` does not return, and it is the same call the C half
    //         makes on a fatal error. Nothing after it is reachable.
    unsafe { abort() }
}

#[cfg(not(test))]
extern "C" {
    fn abort() -> !;
}

/// The prebuilt `core` in a toolchain is compiled with unwinding on, and one of
/// its objects carries a weak reference to the personality routine even when
/// the crate being linked cannot unwind. Nothing calls it - every panic here
/// goes to `abort` - but the reference still has to resolve, and without a
/// definition the link fails on a symbol whose absence says nothing about
/// whether this code is correct.
///
/// Defining it is the smallest thing that answers the reference without
/// dragging in the unwinder an injected process has no use for. It is absent
/// under `cfg(test)`, where the harness is a `std` binary that already has one.
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[cfg(test)]
mod tests;
